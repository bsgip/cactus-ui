import {
  Button,
  Flex,
  Heading,
} from '@radix-ui/themes';
import { useQuery } from '@tanstack/react-query';
import { useEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';

import {
  fetchComplianceFormData,
  fetchComplianceRequest,
  type ComplianceRequestPayload,
} from '../api/compliance';
import type {
  ComplianceFormDataResponse,
  ComplianceRequestResponse,
  RunResponse,
} from '../api/types';
import { ErrorAlert } from '../components/ErrorAlert';
import { PageSpinner } from '../components/PageSpinner';
import { useConfirm } from '../components/useConfirm';
import { useDocumentTitle } from '../hooks/useDocumentTitle';
import StandardStep from '../components/StandardStep';
import RunSelectionStep from '../components/RunSelectionStep';
import { Mode, FormState } from '../utils/complianceRequestWizard';
import DerDetailsStep from '../components/DerDetailsStep';
import SoftwareClientDetailsStep from '../components/SoftwareClientDetailsStep';
import Wizard from '../components/Wizard';


const STEP_TITLES = ['Compliance Details', 'Run Selection', 'DER Details', 'Software Client Details'];


function emptyForm(): FormState {
  return {
    csip_aus_version: '',
    witnessed_at: '',
    classes: new Set(),
    runByProcedure: {},
    der_brand: '',
    der_oem: '',
    der_series: '',
    der_representative_models: '',
    software_client_type: 'direct',
    software_client_providers: '',
    software_client_versions: '',
    onsite_hardware_details: '',
  };
}

// Runs grouped by their test procedure, for the per-procedure run selectors.
function groupRuns(runs: RunResponse[]): Record<string, RunResponse[]> {
  const result: Record<string, RunResponse[]> = {};
  for (const run of runs) {
    (result[run.test_procedure_id] ??= []).push(run);
  }
  return result;
}

export function ComplianceRequestPage({ isAdminView }: { isAdminView: boolean }) {
  useDocumentTitle('Compliance Request - CACTUS');
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const { confirm, confirmDialog } = useConfirm();

  const prefillId = searchParams.get('prefill');
  const prefillClasses = searchParams.get('prefill-classes') === 'true';
  const prefillRuns = searchParams.get('prefill-runs') === 'true';
  const action = searchParams.get('action');
  const mode: Mode = action === 'edit' ? 'edit' : action === 'view' ? 'view' : 'new';
  const readOnly = mode === 'view';
  const listPath = isAdminView ? '/admin/compliance' : '/compliance';
  const requestId = prefillId ? Number(prefillId) : null;

  // The request to prefill from: passed via navigation state from the list, else fetched.
  const stateRequest = (location.state as { request?: ComplianceRequestResponse } | null)?.request;
  const formDataQuery = useQuery({
    queryKey: ['compliance', 'form-data'],
    queryFn: fetchComplianceFormData,
  });
  const prefillQuery = useQuery({
    queryKey: ['compliance', 'request', requestId],
    queryFn: () => fetchComplianceRequest(requestId as number),
    enabled: requestId !== null && !stateRequest,
  });
  const prefillRequest = stateRequest ?? prefillQuery.data;

  const [step, setStep] = useState(0);
  const [form, setForm] = useState<FormState>(emptyForm);
  const [actionError, setActionError] = useState<string | null>(null);
  const initialised = useRef(false);

  const formData = formDataQuery.data;

  // Initialise the form once both the supporting data and any prefill request are available.
  useEffect(() => {
    if (initialised.current || !formData) return;
    if (requestId !== null && !prefillRequest) return; // still waiting on the prefill request
    initialised.current = true;
    setForm(buildInitialForm(formData, prefillRequest, { prefillClasses, prefillRuns }));
  }, [formData, prefillRequest, requestId, prefillClasses, prefillRuns]);

  const runsByProcedure = useMemo(() => groupRuns(formData?.successful_runs ?? []), [formData]);
  const completedSet = useMemo(
    () => new Set(formData?.completed_test_procedures ?? []),
    [formData]
  );

  const version = form.csip_aus_version;
  const classMap = formData?.tests_by_version_and_class[version] ?? {};
  const classesForVersion = useMemo(() => Object.keys(classMap).sort(), [classMap]);

  // Classes that are both selected and valid for the current version.
  const activeClasses = useMemo(
    () => classesForVersion.filter((c) => form.classes.has(c)),
    [classesForVersion, form.classes]
  );

  // Required-but-incomplete tests, by class (no successful run yet).
  const missingByClass = useMemo(() => {
    const result: Record<string, string[]> = {};
    for (const c of activeClasses) {
      const missing = (classMap[c] ?? []).filter((p) => !completedSet.has(p));
      if (missing.length) result[c] = missing;
    }
    return result;
  }, [activeClasses, classMap, completedSet]);
  const missingCount = useMemo(
    () => new Set(Object.values(missingByClass).flat()).size,
    [missingByClass]
  );

  // Procedures the user has a run for AND that belong to a selected class — these get a run selector.
  const visibleProcedures = useMemo(() => {
    const relevant = new Set(activeClasses.flatMap((c) => classMap[c] ?? []));
    return [...relevant].filter((p) => completedSet.has(p)).sort();
  }, [activeClasses, classMap, completedSet]);

  const update = (patch: Partial<FormState>) => setForm((f) => ({ ...f, ...patch }));

  const toggleClass = (c: string, checked: boolean) => {
    setForm((f) => {
      const classes = new Set(f.classes);
      if (checked) classes.add(c);
      else classes.delete(c);
      return { ...f, classes };
    });
  };

  const setAllClasses = (checked: boolean) =>
    update({ classes: checked ? new Set(classesForVersion) : new Set() });

  const buildPayload = (): ComplianceRequestPayload => ({
    csip_aus_version: form.csip_aus_version,
    witnessed_at: form.witnessed_at,
    classes: activeClasses,
    runs: visibleProcedures.map((p) => form.runByProcedure[p]).filter((r): r is number => !!r),
    der_brand: form.der_brand,
    der_oem: form.der_oem,
    der_series: form.der_series,
    der_representative_models: form.der_representative_models,
    software_client_type: form.software_client_type,
    software_client_providers: form.software_client_providers,
    software_client_versions: form.software_client_versions,
    onsite_hardware_details: form.onsite_hardware_details,
  });

  const goToList = () => navigate(listPath);


  const handleClose = () => {
    if (readOnly) {
      goToList();
      return;
    }
    confirm({
      title: 'Are you sure you want to leave?',
      body: 'You will lose all information entered.',
      confirmLabel: 'Leave',
      cancelLabel: 'Continue with compliance request',
      confirmColor: 'red',
      onConfirm: goToList,
    });
  };

  if (formDataQuery.isPending || (requestId !== null && !stateRequest && prefillQuery.isPending)) {
    return <PageSpinner />;
  }
  if (formDataQuery.error || !formData) {
    return (
      <ErrorAlert message="Failed to fetch test procedures. Unable to continue with the compliance request." />
    );
  }


  const wizardSteps = [
          <StandardStep
            form={form}
            mode={mode}
            readOnly={readOnly}
            versions={formData.csipaus_versions}
            update={update}
          />,
          <RunSelectionStep
            form={form}
            readOnly={readOnly}
            formData={formData}
            classesForVersion={classesForVersion}
            visibleProcedures={visibleProcedures}
            runsByProcedure={runsByProcedure}
            missingByClass={missingByClass}
            missingCount={missingCount}
            toggleClass={toggleClass}
            setAllClasses={setAllClasses}
            update={update}
            isAdminView={isAdminView}
          />,
          <DerDetailsStep form={form} readOnly={readOnly} update={update} />,
          <SoftwareClientDetailsStep form={form} readOnly={readOnly} update={update} />
  ]

  return (
    <Flex direction="column" gap="4">
      {confirmDialog}
      <Flex justify="between" align="center">
        <Heading as="h2" size="6">
          Compliance Request
        </Heading>
        <Button variant="ghost" color="gray" onClick={handleClose}>
          Close
        </Button>
      </Flex>

      {actionError && <ErrorAlert message={actionError} />}

      <Wizard
        step={step}
        setStep={setStep}
        stepTitles={STEP_TITLES}
        steps={wizardSteps}
        form={form}
        activeClasses={activeClasses}
        isAdminView={isAdminView}
        mode={mode}
        setActionError={setActionError}
        buildPayload={buildPayload}
        requestId={requestId}
      />

      <iframe name="complianceFinaliseFrame" title="finalise" style={{ display: 'none' }} />
    </Flex>
  );
}


function buildInitialForm(
  formData: ComplianceFormDataResponse,
  prefill: ComplianceRequestResponse | undefined,
  opts: { prefillClasses: boolean; prefillRuns: boolean }
): FormState {
  const form = emptyForm();
  form.csip_aus_version = prefill?.csip_aus_version || formData.csipaus_versions[0] || '';
  if (prefill) {
    form.witnessed_at = prefill.witnessed_at.split('T')[0];
    form.der_brand = prefill.der_brand;
    form.der_oem = prefill.der_oem;
    form.der_series = prefill.der_series;
    form.der_representative_models = prefill.der_representative_models;
    form.software_client_type = prefill.software_client_type || 'direct';
    form.software_client_providers = prefill.software_client_providers;
    form.software_client_versions = prefill.software_client_versions;
    form.onsite_hardware_details = prefill.onsite_hardware_details;
  }

  const classMap = formData.tests_by_version_and_class[form.csip_aus_version] ?? {};
  const completed = new Set(formData.completed_test_procedures);

  if (prefill && opts.prefillClasses) {
    form.classes = new Set(prefill.classes);
  } else {
    // New request: preselect classes whose required tests all have a successful run.
    form.classes = new Set(
      Object.keys(classMap).filter((c) => (classMap[c] ?? []).every((p) => completed.has(p)))
    );
  }

  // Default each procedure's run to its first successful run, then apply any prefilled selections.
  const runs = formData.successful_runs;
  for (const run of runs) {
    form.runByProcedure[run.test_procedure_id] ??= run.run_id;
  }
  if (prefill && opts.prefillRuns) {
    const procedureByRun = new Map(runs.map((r) => [r.run_id, r.test_procedure_id]));
    for (const runId of prefill.runs) {
      const procedure = procedureByRun.get(runId);
      if (procedure) form.runByProcedure[procedure] = runId;
    }
  }
  return form;
}
