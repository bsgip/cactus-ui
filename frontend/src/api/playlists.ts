import { apiFetch } from './client';
import type {
  PlaylistSession,
  PlaylistTestsResponse,
  RunActionResponse,
} from './types';

export function fetchPlaylistTests(runGroupId: number): Promise<PlaylistTestsResponse> {
  return apiFetch(`/api/group/${runGroupId}/playlist_tests`);
}

export function fetchPlaylistSessions(runGroupId: number): Promise<PlaylistSession[]> {
  return apiFetch(`/api/group/${runGroupId}/playlist_sessions`);
}

export function initPlaylist(
  runGroupId: number,
  procedures: string[]
): Promise<RunActionResponse> {
  return apiFetch(`/api/group/${runGroupId}/playlist`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ procedures }),
  });
}

export function finalisePlaylist(runId: number): Promise<RunActionResponse> {
  return apiFetch(`/api/runs/${runId}/finalise_playlist`, { method: 'POST' });
}
