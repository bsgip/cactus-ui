import { apiFetch } from './client';
import type { ProceduresResponse } from './types';

export function fetchProcedures(): Promise<ProceduresResponse> {
  return apiFetch<ProceduresResponse>('/api/procedures');
}
