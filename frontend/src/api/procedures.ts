import { apiFetch } from './client';
import type { ProceduresResponse, ProcedureYamlResponse } from './types';

export function fetchProcedures(): Promise<ProceduresResponse> {
  return apiFetch<ProceduresResponse>('/api/procedures');
}

export function fetchProcedureYaml(testProcedureId: string): Promise<ProcedureYamlResponse> {
  return apiFetch<ProcedureYamlResponse>(`/api/procedure/${encodeURIComponent(testProcedureId)}`);
}
