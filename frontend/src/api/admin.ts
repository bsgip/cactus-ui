import { apiFetch } from './client';
import type { AdminStatsResponse, AdminUsersResponse } from './types';

export function fetchAdminUsers(): Promise<AdminUsersResponse> {
  return apiFetch('/api/admin/users');
}

export function fetchAdminStats(): Promise<AdminStatsResponse> {
  return apiFetch('/api/admin/stats');
}
