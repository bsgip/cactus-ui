import { apiFetch } from './client';
import type { SessionResponse } from './types';

export function fetchSession(): Promise<SessionResponse> {
  return apiFetch<SessionResponse>('/api/session', { on401: 'throw' });
}
