import { apiFetch } from './client';
import type { ComplianceResponse } from './types';

function apiBase(isAdminView: boolean): string {
  return isAdminView ? '/api/admin' : '/api';
}

export function fetchCompliance(
  runGroupId: number,
  isAdminView: boolean
): Promise<ComplianceResponse> {
  return apiFetch(`${apiBase(isAdminView)}/group/${runGroupId}/compliance`);
}
