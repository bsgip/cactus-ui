import { apiFetch } from './client';
import type {
  AdminComplianceRequestsResponse,
  ComplianceFormDataResponse,
  ComplianceRequestResponse,
  ComplianceRequestsResponse,
} from './types';

// The mutable fields the wizard submits. `witnessed_at` is an ISO date string; the BFF coerces
// it to a UTC datetime and maps this onto the orchestrator's ComplianceRequest(Update)Request.
export interface ComplianceRequestPayload {
  csip_aus_version: string;
  witnessed_at: string;
  classes: string[];
  runs: number[];
  der_brand: string;
  der_oem: string;
  der_series: string;
  der_representative_models: string;
  software_client_type: string;
  software_client_providers: string;
  software_client_versions: string;
  onsite_hardware_details: string;
}

export function fetchComplianceRequests(): Promise<ComplianceRequestsResponse> {
  return apiFetch('/api/compliance/requests');
}

export function fetchAdminComplianceRequests(): Promise<AdminComplianceRequestsResponse> {
  return apiFetch('/api/admin/compliance/requests');
}

export function fetchComplianceRequest(id: number): Promise<ComplianceRequestResponse> {
  return apiFetch(`/api/compliance/requests/${id}`);
}

export function fetchComplianceFormData(): Promise<ComplianceFormDataResponse> {
  return apiFetch('/api/compliance/form-data');
}

export function createComplianceRequest(
  payload: ComplianceRequestPayload
): Promise<ComplianceRequestResponse> {
  return apiFetch('/api/compliance/requests', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export function updateComplianceRequest(
  id: number,
  payload: ComplianceRequestPayload
): Promise<ComplianceRequestResponse> {
  return apiFetch(`/api/compliance/requests/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

// Admin review transitions. `under_review` opens a submitted request for editing; `pushed_back`
// returns it to the user. Pass the edited fields when saving, or just the status to (re)open.
export function adminUpdateComplianceRequest(
  id: number,
  status: 'under_review' | 'pushed_back',
  payload?: Partial<ComplianceRequestPayload>
): Promise<ComplianceRequestResponse> {
  return apiFetch(`/api/admin/compliance/requests/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...payload, status }),
  });
}

export function deleteComplianceRequest(id: number, isAdminView: boolean): Promise<unknown> {
  const base = isAdminView ? '/api/admin/compliance/requests' : '/api/compliance/requests';
  return apiFetch(`${base}/${id}`, { method: 'DELETE' });
}

// Browser-native download URLs (session-cookie auth; the access token never reaches the SPA).
export function complianceArtifactUrl(id: number, isAdminView: boolean): string {
  const base = isAdminView ? '/admin/compliance/requests' : '/compliance/requests';
  return `${base}/${id}/artifact`;
}
