import { type ComplianceFormDataResponse, type ComplianceRequestResponse } from '../api/types';
import { useSession } from '../hooks/useSession';

export type Mode = 'new' | 'edit' | 'view';

export interface FormState {
  cactus_version: string;
  csip_aus_version: string;
  witnessed_at: string;
  classes: Set<string>;
  runByProcedure: Record<string, number>;
  der_brand: string;
  der_oem: string;
  der_series: string;
  der_cec_listed_models: string;
  der_unlisted_models: string;
  der_white_listed_models: string;
  software_client_type: string;
  software_client_name: string;
  software_client_versions: string;
  onsite_hardware_details: string;
}

export function emptyForm(): FormState {
  return {
    cactus_version: '',
    csip_aus_version: '',
    witnessed_at: '',
    classes: new Set(),
    runByProcedure: {},
    der_brand: '',
    der_oem: '',
    der_series: '',
    der_cec_listed_models: '',
    der_unlisted_models: '',
    der_white_listed_models: '',
    software_client_type: 'direct',
    software_client_name: '',
    software_client_versions: '',
    onsite_hardware_details: '',
  };
}

export function buildInitialForm(
  formData: ComplianceFormDataResponse,
  prefill: ComplianceRequestResponse | undefined,
  opts: { prefillClasses: boolean; prefillRuns: boolean },
  cactus_version: string,
): FormState {
  const form = emptyForm();
  form.cactus_version = cactus_version
  form.csip_aus_version = prefill?.csip_aus_version || formData.csipaus_versions[0] || '';
  if (prefill) {
    form.witnessed_at = prefill.witnessed_at.split('T')[0];
    form.der_brand = prefill.der_brand;
    form.der_oem = prefill.der_oem;
    form.der_series = prefill.der_series;
    form.der_cec_listed_models = prefill.der_cec_listed_models;
    form.der_unlisted_models = prefill.der_unlisted_models;
    form.der_white_listed_models = prefill.der_white_listed_models;
    form.software_client_type = prefill.software_client_type || 'direct';
    form.software_client_name = prefill.software_client_name;
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
