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
  is_static_uri: boolean;
  static_uri: string | null;
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
  pen: number | null; // null when pen === 0 (reserved; display as placeholder)
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

// One selectable test in the playlist builder (server.py build_playlist_tests_by_category)
export interface PlaylistTest {
  id: string;
  description: string;
  classes: string[];
}

// GET /api/group/<id>/playlist_tests (server.py api_playlist_tests)
export interface PlaylistTestsResponse {
  tests_by_category: Record<string, PlaylistTest[]>;
  classes: ComplianceClass[];
}

// One run within a playlist session (server.py build_test_status_dict)
export interface PlaylistTestStatus {
  test_procedure_id: string;
  run_id: number;
  status: RunStatus;
  all_criteria_met: boolean | null;
  has_artifacts: boolean;
}

// GET /api/group/<id>/playlist_sessions (server.py api_playlist_sessions)
export interface PlaylistSession {
  playlist_execution_id: string;
  short_id: string;
  first_run_id: number;
  created_at: string;
  test_statuses: PlaylistTestStatus[];
  is_active: boolean;
}

// --- Run status page (run_status.html port) ------------------------------------------

// One run within the playlist banner on the run status page. Built by server.py
// build_test_status_dict (finalised runs) or a minimal fallback for not-yet-fetched runs.
export interface PlaylistRunDisplay {
  test_procedure_id: string;
  run_id: number;
  status: RunStatus;
  all_criteria_met: boolean | null;
  has_artifacts: boolean;
}

// playlist_info in the run status shell (server.py _build_playlist_info)
export interface RunStatusPlaylistInfo {
  name: string;
  started_at: string | null;
  runs: PlaylistRunDisplay[];
  current_order: number | null;
  total: number;
}

// The currently-active run in the playlist, if any (server.py _build_playlist_info)
export interface CurrentActiveRun {
  run_id: number;
  test_procedure_id: string;
  order: number;
}

// GET /api/run/<id> and /api/admin/run/<id> (server.py _build_run_status_shell).
// Page metadata + playlist context; the polled RunnerStatus comes from /status.
export interface RunStatusShell {
  run_id: number;
  run_is_live: boolean;
  run_status: RunStatus | null;
  run_test_uri: string | null;
  run_procedure_id: string | null;
  run_has_artifacts: boolean | null;
  // True for immediate_start procedures (no init phase / power timeline) — the finalised
  // view hides the Active Power Chart when set. See server.py _IMMEDIATE_START_PROCEDURE_IDS.
  is_immediate_start: boolean;
  playlist_info: RunStatusPlaylistInfo | null;
  next_playlist_run_id: number | null;
  current_active_run: CurrentActiveRun | null;
}

// The polled runner status. Mirrors cactus_schema.runner.schema.RunnerStatus, serialised
// by FastAPI with native snake_case field names (NOT dataclass-wizard's camelCase to_json).

// cactus_schema.runner.schema.ClientInteraction
export interface ClientInteraction {
  interaction_type: string;
  timestamp: string;
}

// cactus_schema.runner.schema.CriteriaEntry / PreconditionCheckEntry
export interface CriteriaEntry {
  success: boolean;
  type: string;
  details: string;
}

// cactus_schema.runner.schema.StepEventStatus
export interface StepEventStatus {
  started_at: string | null;
  completed_at: string | null;
  event_status: string | null;
}

// cactus_schema.runner.schema.RequestEntry
export interface RequestEntry {
  url: string;
  path: string;
  method: string;
  status: number;
  timestamp: string;
  step_name: string;
  body_xml_errors: string[];
  request_id: number;
}

// cactus_schema.runner.schema.DataStreamPoint
export interface DataStreamPoint {
  watts: number | null;
  offset: string;
}

// cactus_schema.runner.schema.TimelineDataStreamEntry
export interface TimelineDataStreamEntry {
  label: string;
  data: DataStreamPoint[];
  stepped: boolean;
  dashed: boolean;
}

// cactus_schema.runner.schema.TimelineStatus
export interface TimelineStatus {
  data_streams: TimelineDataStreamEntry[];
  set_max_w: number | null;
  now_offset: string;
}

// cactus_schema.runner.schema.DERCapabilityInfo
export interface DerCapabilityInfo {
  der_type: string | null;
  modes_supported: string[] | null;
  max_w: number | null;
  max_va: number | null;
  max_var: number | null;
  max_var_neg: number | null;
  max_a: number | null;
  max_charge_rate_w: number | null;
  max_discharge_rate_w: number | null;
  max_wh: number | null;
  doe_modes_supported: string[] | null;
}

// cactus_schema.runner.schema.DERSettingsInfo
export interface DerSettingsInfo {
  modes_enabled: string[] | null;
  max_w: number | null;
  max_va: number | null;
  max_var: number | null;
  max_var_neg: number | null;
  max_charge_rate_w: number | null;
  max_discharge_rate_w: number | null;
  grad_w: number | null;
  doe_modes_enabled: string[] | null;
}

// cactus_schema.runner.schema.DERStatusInfo
export interface DerStatusInfo {
  alarm_status: string[] | null;
  inverter_status: string | null;
  operational_mode_status: string | null;
  generator_connect_status: string[] | null;
  storage_connect_status: string[] | null;
  storage_mode_status: string | null;
  state_of_charge_status: number | null;
  local_control_mode_status: string | null;
  manufacturer_status: string | null;
}

// cactus_schema.runner.schema.EndDeviceMetadata
export interface EndDeviceMetadata {
  edevid: number | null;
  lfdi: string | null;
  sfdi: number | null;
  nmi: string | null;
  aggregator_id: number | null;
  set_max_w: number | null;
  doe_modes_enabled: number | null;
  device_category: number | null;
  timezone_id: string | null;
  der_capability: DerCapabilityInfo | null;
  der_settings: DerSettingsInfo | null;
  der_status: DerStatusInfo | null;
}

// GET /api/run/<id>/status (+ admin). 410 Gone once the runner has terminated.
export interface RunnerStatus {
  timestamp_status: string;
  timestamp_initialise: string | null;
  timestamp_start: string | null;
  status_summary: string;
  last_client_interaction: ClientInteraction;
  csip_aus_version: string;
  log_envoy: string;
  criteria: CriteriaEntry[];
  // Older runners (v1.3) may omit this; the precondition card is hidden when absent.
  precondition_checks: CriteriaEntry[] | null;
  instructions: string[] | null;
  test_procedure_name: string;
  step_status: Record<string, StepEventStatus> | null;
  request_history: RequestEntry[];
  timeline: TimelineStatus | null;
  end_device_metadata: EndDeviceMetadata | null;
}

// GET /api/run/<id>/requests/<request_id> (cactus_schema.runner.schema.RequestData)
export interface RequestData {
  request_id: number;
  request: string | null;
  response: string | null;
}

// POST /api/runs/<id>/proceed (+ admin) (cactus_schema.orchestrator.ProceedResponse)
export interface ProceedResponse {
  handled: boolean;
}
