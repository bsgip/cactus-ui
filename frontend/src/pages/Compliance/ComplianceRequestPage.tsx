import {
  Badge,
  Button,
  Callout,
  Checkbox,
  Flex,
  Heading,
  Link,
  Select,
  Table,
  Tabs,
  Text,
  TextArea,
  TextField,
  Tooltip,
} from '@radix-ui/themes';
import { IconAlertTriangle } from '@tabler/icons-react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Link as RouterLink, useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import {
  createComplianceRequest,
  fetchComplianceFormData,
  fetchComplianceRequest,
  finaliseComplianceRequest,
  updateComplianceRequest,
  adminUpdateComplianceRequest,
  type ComplianceRequestPayload,
} from '../../api/compliance';
import type {
  ComplianceFormDataResponse,
  ComplianceRequestResponse,
  RunResponse,
} from '../../api/types';
import { ErrorAlert } from '../../components/ErrorAlert';
import { PageSpinner } from '../../components/PageSpinner';
import { useConfirm } from '../../components/useConfirm';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';

type Mode = 'new' | 'edit' | 'view';

const STEP_TITLES = ['Standard', 'Classes & Runs', 'DER', 'Software Client'];

interface FormState {
  csip_aus_version: string;
  witnessed_at: string;
  classes: Set<string>;
  runByProcedure: Record<string, number>;
  der_brand: string;
  der_oem: string;
  der_series: string;
  der_representative_models: string;
  software_client_type: string;
  software_client_providers: string;
  software_client_versions: string;
  onsite_hardware_details: string;
}

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

  const onError = (err: Error) => setActionError(err.message);
  const goToList = () => navigate(listPath);

  const createMutation = useMutationSafe(
    () => createComplianceRequest(buildPayload()),
    goToList,
    onError
  );
  const updateMutation = useMutationSafe(
    () => updateComplianceRequest(requestId as number, buildPayload()),
    goToList,
    onError
  );
  const adminSaveMutation = useMutationSafe(
    () => adminUpdateComplianceRequest(requestId as number, 'under_review', buildPayload()),
    goToList,
    onError
  );
  const adminPushBackMutation = useMutationSafe(
    () => adminUpdateComplianceRequest(requestId as number, 'pushed_back', buildPayload()),
    goToList,
    onError
  );
  const finaliseMutation = useMutationSafe(
    () => finaliseComplianceRequest(requestId as number),
    goToList,
    onError
  );

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

  const isLastStep = step === STEP_TITLES.length - 1;
  const submitDisabled = !form.witnessed_at || activeClasses.length === 0;

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

      <Tabs.Root value={String(step)} onValueChange={(v) => setStep(Number(v))}>
        <Tabs.List>
          {STEP_TITLES.map((title, i) => (
            <Tabs.Trigger key={title} value={String(i)}>
              {i + 1}. {title}
            </Tabs.Trigger>
          ))}
        </Tabs.List>

        <Tabs.Content value="0">
          <StandardStep
            form={form}
            mode={mode}
            readOnly={readOnly}
            versions={formData.csipaus_versions}
            update={update}
          />
        </Tabs.Content>

        <Tabs.Content value="1">
          <ClassesRunsStep
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
          />
        </Tabs.Content>

        <Tabs.Content value="2">
          <DerStep form={form} readOnly={readOnly} update={update} />
        </Tabs.Content>

        <Tabs.Content value="3">
          <SoftwareClientStep form={form} readOnly={readOnly} update={update} />
        </Tabs.Content>
      </Tabs.Root>

      <Flex justify="end" gap="2" wrap="wrap">
        {step > 0 && (
          <Button variant="soft" color="gray" onClick={() => setStep(step - 1)}>
            Back
          </Button>
        )}
        {!isLastStep && <Button onClick={() => setStep(step + 1)}>Next</Button>}

        {isLastStep && !isAdminView && mode === 'new' && (
          <Button
            disabled={submitDisabled}
            loading={createMutation.isPending}
            onClick={() => createMutation.mutate()}
          >
            Submit
          </Button>
        )}
        {isLastStep && !isAdminView && mode === 'edit' && (
          <Button
            disabled={submitDisabled}
            loading={updateMutation.isPending}
            onClick={() => updateMutation.mutate()}
          >
            Update
          </Button>
        )}
        {isLastStep && isAdminView && mode === 'edit' && (
          <>
            <Button
              variant="soft"
              loading={adminSaveMutation.isPending}
              onClick={() => adminSaveMutation.mutate()}
            >
              Save &amp; Exit
            </Button>
            <Button
              color="orange"
              loading={adminPushBackMutation.isPending}
              onClick={() => adminPushBackMutation.mutate()}
            >
              Push Back
            </Button>
            <Button
              color="green"
              loading={finaliseMutation.isPending}
              onClick={() => finaliseMutation.mutate()}
            >
              Finalise
            </Button>
          </>
        )}
      </Flex>
    </Flex>
  );
}

// useMutation wrapper that keeps the call sites terse (this page fires several near-identical mutations).
function useMutationSafe(
  fn: () => Promise<unknown>,
  onSuccess: () => void,
  onError: (e: Error) => void
) {
  return useMutation({ mutationFn: fn, onSuccess, onError });
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

function StandardStep({
  form,
  mode,
  readOnly,
  versions,
  update,
}: {
  form: FormState;
  mode: Mode;
  readOnly: boolean;
  versions: string[];
  update: (patch: Partial<FormState>) => void;
}) {
  return (
    <Flex direction="column" gap="4" pt="4">
      {mode === 'new' && (
        <Callout.Root color="yellow">
          <Callout.Icon>
            <IconAlertTriangle size={16} />
          </Callout.Icon>
          <Callout.Text>
            Witness testing must be completed before a compliance request can be submitted. If you
            are yet to complete witness testing, please contact{' '}
            <Link href="mailto:support@bsgip.com">support@bsgip.com</Link> to arrange a date.
          </Callout.Text>
        </Callout.Root>
      )}
      <label>
        <Text as="div" size="2" weight="bold" mb="1">
          Compliance Standard
        </Text>
        <Select.Root
          value={form.csip_aus_version}
          onValueChange={(v) => update({ csip_aus_version: v })}
          disabled={readOnly}
        >
          <Select.Trigger placeholder="Select a version" />
          <Select.Content>
            {versions.map((v) => (
              <Select.Item key={v} value={v}>
                CSIP-Aus {v}
              </Select.Item>
            ))}
          </Select.Content>
        </Select.Root>
        <Text as="div" size="1" color="gray" mt="1">
          A compliance request can only be made against one compliance standard at a time.
        </Text>
      </label>
      <label>
        <Text as="div" size="2" weight="bold" mb="1">
          Witness Testing Date
        </Text>
        <TextField.Root
          type="date"
          value={form.witnessed_at}
          onChange={(e) => update({ witnessed_at: e.target.value })}
          disabled={readOnly}
        />
        <Text as="div" size="1" color="gray" mt="1">
          The date when in-person witness testing was performed.
        </Text>
      </label>
    </Flex>
  );
}

function ClassesRunsStep({
  form,
  readOnly,
  formData,
  classesForVersion,
  visibleProcedures,
  runsByProcedure,
  missingByClass,
  missingCount,
  toggleClass,
  setAllClasses,
  update,
  isAdminView,
}: {
  form: FormState;
  readOnly: boolean;
  formData: ComplianceFormDataResponse;
  classesForVersion: string[];
  visibleProcedures: string[];
  runsByProcedure: Record<string, RunResponse[]>;
  missingByClass: Record<string, string[]>;
  missingCount: number;
  toggleClass: (c: string, checked: boolean) => void;
  setAllClasses: (checked: boolean) => void;
  update: (patch: Partial<FormState>) => void;
  isAdminView: boolean;
}) {
  const descriptions = useMemo(
    () => new Map(formData.compliance_classes.map((c) => [c.name, c.description])),
    [formData.compliance_classes]
  );

  return (
    <Flex direction="column" gap="4" pt="4">
      <Flex direction="column" gap="2">
        <Heading as="h3" size="4">
          Classes
        </Heading>
        <Text size="2">Choose all the compliance classes you want to be assessed under.</Text>
        {!readOnly && (
          <Flex gap="2">
            <Button size="1" onClick={() => setAllClasses(true)}>
              Select All
            </Button>
            <Button size="1" variant="soft" color="gray" onClick={() => setAllClasses(false)}>
              Deselect All
            </Button>
          </Flex>
        )}
        <Flex gap="3" wrap="wrap" mt="1">
          {classesForVersion.map((c) => (
            <Tooltip key={c} content={descriptions.get(c) || c}>
              <Text as="label" size="2" style={{ minWidth: 180 }}>
                <Flex gap="2" align="center">
                  <Checkbox
                    checked={form.classes.has(c)}
                    onCheckedChange={(checked) => toggleClass(c, checked === true)}
                    disabled={readOnly}
                  />
                  {c}
                </Flex>
              </Text>
            </Tooltip>
          ))}
        </Flex>
      </Flex>

      {missingCount > 0 && (
        <Callout.Root color="red">
          <Callout.Icon>
            <IconAlertTriangle size={16} />
          </Callout.Icon>
          <Callout.Text>
            <Text as="div" weight="bold" mb="1">
              Runs Missing
            </Text>
            Some chosen compliance classes do not have successful test runs:
            <ul style={{ margin: '8px 0' }}>
              {Object.entries(missingByClass).map(([c, missing]) => (
                <li key={c}>
                  <strong>Class {c}:</strong> {missing.join(', ')}
                </li>
              ))}
            </ul>
            There is a total of <strong>{missingCount}</strong> missing runs. You must complete the
            required tests or remove the incomplete classes before{' '}
            {isAdminView ? 'finalising' : 'submitting'}.
          </Callout.Text>
        </Callout.Root>
      )}

      {visibleProcedures.length > 0 && (
        <Flex direction="column" gap="2">
          <Heading as="h3" size="4">
            Runs
          </Heading>
          <Text size="2">
            For each test procedure, choose which run you want assessed. Only successful (finalised
            and passing) runs are shown.
          </Text>
          <Table.Root variant="surface">
            <Table.Body>
              {visibleProcedures.map((p) => (
                <Table.Row key={p}>
                  <Table.RowHeaderCell>
                    <Link asChild>
                      <RouterLink to={`/procedure/${p}`}>{p}</RouterLink>
                    </Link>
                  </Table.RowHeaderCell>
                  <Table.Cell>
                    <Select.Root
                      value={form.runByProcedure[p] ? String(form.runByProcedure[p]) : undefined}
                      onValueChange={(v) =>
                        update({ runByProcedure: { ...form.runByProcedure, [p]: Number(v) } })
                      }
                      disabled={readOnly}
                    >
                      <Select.Trigger placeholder="Select a run" />
                      <Select.Content>
                        {(runsByProcedure[p] ?? []).map((run) => (
                          <Select.Item key={run.run_id} value={String(run.run_id)}>
                            #{run.run_id}
                          </Select.Item>
                        ))}
                      </Select.Content>
                    </Select.Root>
                  </Table.Cell>
                  <Table.Cell>
                    {form.runByProcedure[p] && (
                      <Link asChild>
                        <RouterLink to={`/run/${form.runByProcedure[p]}`}>View</RouterLink>
                      </Link>
                    )}
                  </Table.Cell>
                </Table.Row>
              ))}
            </Table.Body>
          </Table.Root>
        </Flex>
      )}
      {activeClassesEmpty(form, classesForVersion) && (
        <Badge color="gray">Select at least one compliance class to choose runs.</Badge>
      )}
    </Flex>
  );
}

function activeClassesEmpty(form: FormState, classesForVersion: string[]): boolean {
  return !classesForVersion.some((c) => form.classes.has(c));
}

function FieldRow({
  label,
  help,
  children,
}: {
  label: string;
  help?: string;
  children: React.ReactNode;
}) {
  return (
    <label>
      <Text as="div" size="2" weight="bold" mb="1">
        {label}
      </Text>
      {children}
      {help && (
        <Text as="div" size="1" color="gray" mt="1">
          {help}
        </Text>
      )}
    </label>
  );
}

function DerStep({
  form,
  readOnly,
  update,
}: {
  form: FormState;
  readOnly: boolean;
  update: (patch: Partial<FormState>) => void;
}) {
  return (
    <Flex direction="column" gap="4" pt="4">
      <Heading as="h3" size="4">
        DER
      </Heading>
      <FieldRow label="Brand">
        <TextField.Root
          value={form.der_brand}
          onChange={(e) => update({ der_brand: e.target.value })}
          disabled={readOnly}
        />
      </FieldRow>
      <FieldRow label="OEM">
        <TextField.Root
          value={form.der_oem}
          onChange={(e) => update({ der_oem: e.target.value })}
          disabled={readOnly}
        />
      </FieldRow>
      <FieldRow label="Series" help="The series or product line the DER belongs to.">
        <TextField.Root
          value={form.der_series}
          onChange={(e) => update({ der_series: e.target.value })}
          disabled={readOnly}
        />
      </FieldRow>
      <FieldRow
        label="Representative Models"
        help="Models in the DER series. Models must use the same software and hardware configuration; they may differ in rated power or phases."
      >
        <TextArea
          rows={3}
          value={form.der_representative_models}
          onChange={(e) => update({ der_representative_models: e.target.value })}
          disabled={readOnly}
        />
      </FieldRow>
    </Flex>
  );
}

function SoftwareClientStep({
  form,
  readOnly,
  update,
}: {
  form: FormState;
  readOnly: boolean;
  update: (patch: Partial<FormState>) => void;
}) {
  return (
    <Flex direction="column" gap="4" pt="4">
      <Heading as="h3" size="4">
        Software Client
      </Heading>
      <FieldRow
        label="Type"
        help="Direct - the DER connects with its own client representing a single site. Proxy (Aggregator) - DER(s) connect via a communications aggregator that may represent many sites."
      >
        <Select.Root
          value={form.software_client_type}
          onValueChange={(v) => update({ software_client_type: v })}
          disabled={readOnly}
        >
          <Select.Trigger />
          <Select.Content>
            <Select.Item value="direct">Direct</Select.Item>
            <Select.Item value="proxy">Proxy (Aggregator)</Select.Item>
          </Select.Content>
        </Select.Root>
      </FieldRow>
      <FieldRow
        label="Provider(s)"
        help="The software client may be provided by an OEM or third-party."
      >
        <TextField.Root
          value={form.software_client_providers}
          onChange={(e) => update({ software_client_providers: e.target.value })}
          disabled={readOnly}
        />
      </FieldRow>
      <FieldRow
        label="Version(s)"
        help="The full name and version(s) of all software clients, plus any intermediate cloud server(s) or platform(s)."
      >
        <TextField.Root
          value={form.software_client_versions}
          onChange={(e) => update({ software_client_versions: e.target.value })}
          disabled={readOnly}
        />
      </FieldRow>
      <Heading as="h3" size="4">
        On-site Hardware
      </Heading>
      <FieldRow
        label="Details"
        help="Makes and models of any on-site gateway, control, EMS device or external accessories that are part of the software client implementation."
      >
        <TextArea
          rows={3}
          value={form.onsite_hardware_details}
          onChange={(e) => update({ onsite_hardware_details: e.target.value })}
          disabled={readOnly}
        />
      </FieldRow>
    </Flex>
  );
}
