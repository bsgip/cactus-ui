// Public barrel for the /api wire types. Almost everything here is generated from the Python
// dataclasses (cactus_ui.api_models + cactus_schema), the single source of truth — edit a
// dataclass and regenerate (uv run python scripts/export_api_schema.py && npm run
// generate:types); never hand-edit ./generated/types.ts. Pages import from this barrel, not
// from ./generated directly.

export * from './generated/types';

import type { RunStatusResponse, TestProcedureRunSummaryResponse } from './generated/types';

// Short aliases for generated names used widely across the UI.
export type RunStatus = RunStatusResponse;
export type TestProcedureRunSummary = TestProcedureRunSummaryResponse;

// The two shapes that aren't generated:

// Pagination is a generic envelope (json-schema-to-typescript can't express generics), so it
// stays hand-written. Its fields mirror cactus_schema.orchestrator.Pagination, serialised by
// server.py paginated_json.
export interface Pagination<T> {
  total_pages: number;
  total_items: number;
  page_size: number;
  current_page: number;
  prev_page: number | null;
  next_page: number | null;
  items: T[];
}

// The 401 body from /api/session — an error envelope (not a serialised dataclass), kept
// hand-written for its literal `error` discriminant.
export interface UnauthenticatedResponse {
  error: 'unauthenticated';
  login_banner_message: string | null;
}
