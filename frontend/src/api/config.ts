import { apiDownload, apiFetch } from './client';
import type { ConfigResponse, RunGroupResponse } from './types';

export function fetchConfig(): Promise<ConfigResponse> {
  return apiFetch('/api/config');
}

export function updatePen(pen: number): Promise<Record<string, never>> {
  return apiFetch('/api/config/pen', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pen }),
  });
}

export function updateDomain(subscription_domain: string): Promise<Record<string, never>> {
  return apiFetch('/api/config/domain', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subscription_domain }),
  });
}

export function createRunGroup(csip_aus_version: string): Promise<RunGroupResponse> {
  return apiFetch('/api/run_groups', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ csip_aus_version }),
  });
}

export function updateRunGroupName(run_group_id: number, name: string): Promise<RunGroupResponse> {
  return apiFetch(`/api/run_groups/${run_group_id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  });
}

export function deleteRunGroup(run_group_id: number): Promise<Record<string, never>> {
  return apiFetch(`/api/run_groups/${run_group_id}`, { method: 'DELETE' });
}

export type CertificateType = 'device' | 'aggregator';

// Set (comma separated run group ids) by the BFF when a new certificate couldn't be assigned to
// some of the requested run groups. The certificate itself was still created and downloaded.
export const HEADER_UNASSIGNED_RUN_GROUPS = 'X-Cactus-Unassigned-Run-Groups';

export interface CreateCertificateResult {
  // Requested run groups the new certificate could NOT be assigned to.
  unassignedRunGroupIds: number[];
}

// Certificate generation returns the new bundle (incl. the private key, which can't be fetched
// again) as a ZIP download, so it goes through apiDownload rather than apiFetch.
export async function createCertificate(
  name: string,
  type: CertificateType,
  run_group_ids: number[]
): Promise<CreateCertificateResult> {
  const headers = await apiDownload('/config/certificates', 'certificate.zip', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, type, run_group_ids }),
  });
  const unassigned = headers.get(HEADER_UNASSIGNED_RUN_GROUPS);
  return {
    unassignedRunGroupIds: unassigned ? unassigned.split(',').map(Number) : [],
  };
}

export async function regenerateCertificate(certificate_id: number): Promise<void> {
  await apiDownload(`/config/certificates/${certificate_id}/regenerate`, 'certificate.zip', {
    method: 'POST',
  });
}

// Plain GET - used as an <a href> so the browser handles the download natively.
export function certificateDownloadUrl(certificate_id: number): string {
  return `/config/certificates/${certificate_id}`;
}

export function deleteCertificate(certificate_id: number): Promise<Record<string, never>> {
  return apiFetch(`/api/certificates/${certificate_id}`, { method: 'DELETE' });
}

export function assignRunGroupCertificate(
  run_group_id: number,
  certificate_id: number
): Promise<RunGroupResponse> {
  return apiFetch(`/api/run_groups/${run_group_id}/certificate`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ certificate_id }),
  });
}

export function unassignRunGroupCertificate(run_group_id: number): Promise<RunGroupResponse> {
  return apiFetch(`/api/run_groups/${run_group_id}/certificate`, { method: 'DELETE' });
}
