import { apiFetch } from './client';
import type { ProceedResponse, RequestData, RunStatusShell, RunnerStatus } from './types';

function apiBase(isAdminView: boolean): string {
  return isAdminView ? '/api/admin' : '/api';
}

// Page shell: run metadata + playlist context (server.py _build_run_status_shell).
export function fetchRunStatusShell(runId: number, isAdminView: boolean): Promise<RunStatusShell> {
  return apiFetch(`${apiBase(isAdminView)}/run/${runId}`);
}

// Polled RunnerStatus. Throws ApiError(410) once the runner has terminated — callers
// use that to flip back to the finalised view.
export function fetchRunnerStatus(runId: number, isAdminView: boolean): Promise<RunnerStatus> {
  return apiFetch(`${apiBase(isAdminView)}/run/${runId}/status`);
}

// Raw request/response for the request-details modal. Shared by both views.
export function fetchRequestDetails(runId: number, requestId: number): Promise<RequestData> {
  return apiFetch(`/api/run/${runId}/requests/${requestId}`);
}

export function sendProceed(runId: number, isAdminView: boolean): Promise<ProceedResponse> {
  return apiFetch(`${apiBase(isAdminView)}/runs/${runId}/proceed`, { method: 'POST' });
}
