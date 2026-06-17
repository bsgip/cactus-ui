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

// Mirrors cactus_schema.orchestrator.TestProcedureResponse
export interface TestProcedureResponse {
  test_procedure_id: string;
  description: string;
  category: string;
  classes: string[];
  target_versions: string[];
}

// GET /api/procedures (server.py api_procedures)
export interface ProceduresResponse {
  procedures: TestProcedureResponse[];
}

// GET /api/procedure/<id> (server.py api_procedure_yaml)
export interface ProcedureYamlResponse {
  test_procedure_id: string;
  yaml: string;
}

// Mirrors cactus_schema.orchestrator.Pagination (serialised by server.py paginated_json)
export interface Pagination<T> {
  total_pages: number;
  total_items: number;
  page_size: number;
  current_page: number;
  prev_page: number | null;
  next_page: number | null;
  items: T[];
}

// Mirrors cactus_schema.orchestrator.RunStatusResponse (StrEnum)
export type RunStatus = 'initialised' | 'started' | 'finalised' | 'provisioning' | 'skipped';

// Mirrors cactus_schema.orchestrator.PlaylistRunInfo
export interface PlaylistRunInfo {
  run_id: number;
  test_procedure_id: string;
  status: RunStatus;
}

// Mirrors cactus_schema.orchestrator.RunResponse
export interface RunResponse {
  run_id: number;
  test_procedure_id: string;
  test_url: string;
  status: RunStatus;
  all_criteria_met: boolean | null;
  created_at: string;
  finalised_at: string | null;
  is_device_cert: boolean;
  has_artifacts: boolean;
  playlist_execution_id: string | null;
  playlist_order: number | null;
  playlist_runs: PlaylistRunInfo[] | null;
  classes: string[] | null;
}

// Mirrors cactus_schema.orchestrator.RunGroupResponse
export interface RunGroupResponse {
  run_group_id: number;
  name: string;
  csip_aus_version: string;
  created_at: string;
  is_device_cert: boolean | null;
  certificate_id: number | null;
  certificate_created_at: string | null;
  total_runs: number;
}

// Mirrors cactus_schema.orchestrator.TestProcedureRunSummaryResponse
export interface TestProcedureRunSummary {
  test_procedure_id: string;
  description: string;
  category: string;
  classes: string[] | null;
  run_count: number;
  latest_all_criteria_met: boolean | null;
  latest_run_status: number | null;
  latest_run_id: number | null;
  latest_run_timestamp: string | null;
  immediate_start: boolean;
}

// Mirrors cactus_schema.orchestrator.compliance.ComplianceClass
export interface ComplianceClass {
  name: string;
  description: string;
}

export interface GroupedProcedures {
  slug: string;
  category: string;
  summaries: TestProcedureRunSummary[];
}

// GET /api/group/<id>/procedure_summaries (server.py build_procedure_summaries_json)
export interface ProcedureSummariesResponse {
  grouped_procedures: GroupedProcedures[];
  classes: ComplianceClass[];
  classes_by_test: Record<string, string[]>;
  classes_by_category: Record<string, string[]>;
}

// POST /api/group/<id>/runs and /api/runs/<id>/start|finalise, DELETE /api/runs/<id>
export interface RunActionResponse {
  run_id: number;
}

// Mirrors cactus_schema.orchestrator.CSIPAusVersionResponse
export interface CsipAusVersionResponse {
  version: string;
}

// GET /api/config (server.py api_config)
export interface UserConfig {
  subscription_domain: string;
  is_static_uri: boolean;
  pen: number | null; // null when pen === 0 (reserved; display as placeholder)
  static_uri: string | null;
}

export interface ConfigResponse {
  config: UserConfig;
  run_groups: RunGroupResponse[];
  csip_aus_versions: CsipAusVersionResponse[];
}

// GET /api/admin/users
export interface AdminUserResponse {
  user_id: number;
  subject_id: string;
  name: string | null;
  run_groups: RunGroupResponse[];
  matchable_description: string;
}

export interface AdminUsersResponse {
  users: AdminUserResponse[];
}

// GET /api/group/<id>/compliance (server.py build_compliance_json)
export type ComplianceStatus = 'active' | 'failed' | 'success' | 'runless' | 'unknown';

export interface PerRunStatus {
  test_procedure_id: string;
  description: string;
  latest_run_id: number | null;
  status: ComplianceStatus;
}

export interface ComplianceClassEntry {
  class_name: string;
  class_details: ComplianceClass;
  compliant: boolean;
  per_run_status: PerRunStatus[];
}

export interface ComplianceResponse {
  compliance_by_class: ComplianceClassEntry[];
}

// GET /api/admin/stats
export interface WeekBar {
  month: string;
  year: string;
  count: number;
}

export interface ProcedureStat {
  test_procedure_id: string;
  classes: string[] | null;
  total_runs: number;
  passed: number;
  failed: number;
  latest_passed: number;
  latest_failed: number;
}

export interface UserLeaderboardEntry {
  name: string;
  run_count: number;
}

export interface AdminStatsResponse {
  total_users: number;
  total_run_groups: number;
  total_runs: number;
  total_passed: number;
  total_failed: number;
  max_run_number: number;
  version_counts: Record<string, number>;
  user_leaderboard: UserLeaderboardEntry[];
  procedures: ProcedureStat[];
  runs_per_week: WeekBar[];
}
