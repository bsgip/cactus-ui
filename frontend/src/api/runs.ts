import { apiFetch } from './client';
import type {
  Pagination,
  ProcedureSummariesResponse,
  RunActionResponse,
  RunGroupResponse,
  RunResponse,
} from './types';

function apiBase(isAdminView: boolean): string {
  return isAdminView ? '/api/admin' : '/api';
}

// The admin endpoint can't identify the target user from the token, so it takes the
// run group being viewed as a query param (mirrors orchestrator.admin_fetch_run_groups).
export function fetchRunGroups(
  isAdminView: boolean,
  runGroupId?: number
): Promise<Pagination<RunGroupResponse>> {
  return isAdminView
    ? apiFetch(`/api/admin/run_groups?run_group_id=${runGroupId}`)
    : apiFetch('/api/run_groups');
}

export function fetchProcedureSummaries(
  runGroupId: number,
  isAdminView: boolean
): Promise<ProcedureSummariesResponse> {
  return apiFetch(`${apiBase(isAdminView)}/group/${runGroupId}/procedure_summaries`);
}

export function fetchProcedureRuns(
  runGroupId: number,
  testProcedureId: string,
  isAdminView: boolean
): Promise<Pagination<RunResponse>> {
  return apiFetch(
    `${apiBase(isAdminView)}/group/${runGroupId}/procedure_runs/${encodeURIComponent(testProcedureId)}`
  );
}

export function fetchActiveRuns(
  runGroupId: number,
  isAdminView: boolean
): Promise<Pagination<RunResponse>> {
  return apiFetch(`${apiBase(isAdminView)}/group/${runGroupId}/active_runs`);
}

export function initRun(runGroupId: number, testProcedureId: string): Promise<RunActionResponse> {
  return apiFetch(`/api/group/${runGroupId}/runs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ test_procedure_id: testProcedureId }),
  });
}

export function startRun(runId: number): Promise<RunActionResponse> {
  return apiFetch(`/api/runs/${runId}/start`, { method: 'POST' });
}

export function finaliseRun(runId: number): Promise<RunActionResponse> {
  return apiFetch(`/api/runs/${runId}/finalise`, { method: 'POST' });
}

export function deleteRun(runId: number): Promise<RunActionResponse> {
  return apiFetch(`/api/runs/${runId}`, { method: 'DELETE' });
}
