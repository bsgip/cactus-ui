// TS mirrors of the Flask /api JSON shapes (snake_case at the boundary, per MIGRATION.md).

// GET /api/session (server.py api_session)
export interface SessionResponse {
  username: string | null;
  permissions: string[];
  version: string;
  support_email: string;
  banner_message: string | null;
  hosted_images: string[];
}

// 401 body from /api/session
export interface UnauthenticatedResponse {
  error: 'unauthenticated';
  login_banner_message: string | null;
}
