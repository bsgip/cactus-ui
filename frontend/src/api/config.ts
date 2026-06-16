import { apiFetch } from './client';
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

export function updateStaticUri(is_static_uri: boolean): Promise<Record<string, never>> {
  return apiFetch('/api/config/static_uri', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ is_static_uri }),
  });
}

export function createRunGroup(csip_aus_version: string): Promise<RunGroupResponse> {
  return apiFetch('/api/run_groups', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ csip_aus_version }),
  });
}

export function updateRunGroupName(
  run_group_id: number,
  name: string
): Promise<RunGroupResponse> {
  return apiFetch(`/api/run_groups/${run_group_id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  });
}

export function deleteRunGroup(run_group_id: number): Promise<Record<string, never>> {
  return apiFetch(`/api/run_groups/${run_group_id}`, { method: 'DELETE' });
}
