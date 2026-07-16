 export type Mode = 'new' | 'edit' | 'view';

export interface FormState {
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

export function emptyForm(): FormState {
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
