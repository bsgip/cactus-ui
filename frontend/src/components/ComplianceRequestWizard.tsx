import Wizard from './Wizard';
import { ClientWizardPager, AdminWizardPager } from './ComplianceRequestWizardPager';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useEffect, useMemo, useRef, useState } from 'react';

import { type ComplianceRequestPayload } from '../api/compliance';
import type { RunResponse, ComplianceFormDataResponse } from '../api/types';
import StandardStep from '../components/StandardStep';
import RunSelectionStep from '../components/RunSelectionStep';
import DerDetailsStep from '../components/DerDetailsStep';
import SoftwareClientDetailsStep from '../components/SoftwareClientDetailsStep';
import { Mode, FormState, emptyForm, buildInitialForm } from '../utils/complianceRequestWizard';

// Runs grouped by their test procedure, for the per-procedure run selectors.
function groupRuns(runs: RunResponse[]): Record<string, RunResponse[]> {
  const result: Record<string, RunResponse[]> = {};
  for (const run of runs) {
    (result[run.test_procedure_id] ??= []).push(run);
  }
  return result;
}

interface ComplianceRequestWizardProps {
  isAdminView: boolean;
  setActionError: any;
  formData: ComplianceFormDataResponse,
  prefillRequest: any;
}

function ComplianceRequestWizard({ isAdminView, setActionError, formData, prefillRequest }: ComplianceRequestWizardProps) {

  const [step, setStep] = useState(0);
  const stepTitles = ['Compliance Details', 'Run Selection', 'DER Details', 'Software Client Details'];

  const onError = (err: Error) => setActionError(err.message);
  const navigate = useNavigate();


  const [searchParams] = useSearchParams();

  const prefillId = searchParams.get('prefill');
  const requestId = prefillId ? Number(prefillId) : null;

  const prefillClasses = searchParams.get('prefill-classes') === 'true';
  const prefillRuns = searchParams.get('prefill-runs') === 'true';

  const action = searchParams.get('action');
  const mode: Mode = action === 'edit' ? 'edit' : action === 'view' ? 'view' : 'new';
  const readOnly = mode === 'view';

  const [form, setForm] = useState<FormState>(emptyForm);
  const initialised = useRef(false);

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
  const steps = [
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
  const wizardPager = isAdminView ?
    <AdminWizardPager
      step={step}
      stepCount={stepTitles.length}
      setStep={setStep}
      mode={mode}
      buildPayload={buildPayload}
      requestId={requestId}
      gotoComplianceRequests={() => navigate('/admin/compliance')}
      onError={onError}
    /> :
    <ClientWizardPager
      step={step}
      stepCount={stepTitles.length}
      form={form}
      activeClasses={activeClasses}
      setStep={setStep}
      mode={mode}
      buildPayload={buildPayload}
      requestId={requestId}
      gotoComplianceRequests={() => navigate('/compliance')}
      onError={onError}
    />

  return (
    <Wizard
      step={step}
      setStep={setStep}
      stepTitles={stepTitles}
      steps={steps}
      wizardPager={wizardPager}
    />

  );
}

export default ComplianceRequestWizard;
