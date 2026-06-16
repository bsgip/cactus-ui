import { apiFetch } from './client';
import type { AdminUsersResponse } from './types';

export function fetchAdminUsers(): Promise<AdminUsersResponse> {
  return apiFetch('/api/admin/users');
}
