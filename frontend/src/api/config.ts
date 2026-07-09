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

// Cert generation returns the new bundle as a ZIP download; the Flask endpoints read
// form-encoded bodies (they predate the SPA), hence URLSearchParams rather than JSON.
export function generateRunGroupCert(
  run_group_id: number,
  type: 'device' | 'aggregator'
): Promise<void> {
  return apiDownload(`/config/run_group/${run_group_id}/cert`, 'certificate.zip', {
    method: 'POST',
    body: new URLSearchParams({ type }),
  });
}

export function generateSharedCert(): Promise<void> {
  return apiDownload('/config/shared_cert', 'certificate.zip', { method: 'POST' });
}
