import { apiFetch } from './client';
import type {
  PlaylistSession,
  PlaylistTestsResponse,
  RunActionResponse,
  UpdatePlaylistResponse,
} from './types';

export function fetchPlaylistTests(runGroupId: number): Promise<PlaylistTestsResponse> {
  return apiFetch(`/api/group/${runGroupId}/playlist_tests`);
}

export function fetchPlaylistSessions(runGroupId: number): Promise<PlaylistSession[]> {
  return apiFetch(`/api/group/${runGroupId}/playlist_sessions`);
}

export function initPlaylist(runGroupId: number, procedures: string[]): Promise<RunActionResponse> {
  return apiFetch(`/api/group/${runGroupId}/playlist`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ procedures }),
  });
}

export function finalisePlaylist(runId: number): Promise<RunActionResponse> {
  return apiFetch(`/api/runs/${runId}/finalise_playlist`, { method: 'POST' });
}

// Replaces the upcoming (not-yet-run) tail of runId's playlist. expectedActiveRunId guards
// against a stale edit (the playlist advanced since the caller last fetched it) - the
// orchestrator returns 409 (ApiError.status === 409) when it doesn't match the current active run.
export function updatePlaylist(
  runId: number,
  testProcedureIds: string[],
  expectedActiveRunId: number
): Promise<UpdatePlaylistResponse> {
  return apiFetch(`/api/run/${runId}/playlist`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      test_procedure_ids: testProcedureIds,
      expected_active_run_id: expectedActiveRunId,
    }),
  });
}
