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
