import { apiFetch } from './client';
import type { ReleaseNotesResponse } from './types';

export function fetchReleaseNotes(): Promise<ReleaseNotesResponse> {
  return apiFetch('/api/release-notes');
}
