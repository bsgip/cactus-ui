/* eslint-disable */
/**
 * AUTO-GENERATED — DO NOT EDIT BY HAND.
 *
 * These types mirror the Python dataclasses that define the /api wire contract
 * (cactus_ui.api_models + cactus_schema runner/orchestrator schemas). Regenerate with:
 *   uv run python scripts/export_api_schema.py        # dataclasses -> schema.json
 *   (cd frontend && npm run generate:types)           # schema.json -> this file
 */

export type ClientInteractionType =
  | 'Runner Started'
  | 'Test Procedure Initialised'
  | 'Test Procedure Started'
  | 'Request Proxied'
  | 'TEST_PROCEDURE_FINALIZED';
/**
 * Per-test compliance state derived from its latest run (compliance page).
 */
export type ComplianceStatus = 'active' | 'failed' | 'success' | 'runless' | 'unknown';
export type RunStatusResponse = 'initialised' | 'started' | 'finalised' | 'provisioning' | 'skipped';
/**
 * The set of all available test ID's
 *
 * This should be kept in sync with the current set of client test procedures loaded from the procedures directory
 */
export type TestProcedureId =
  | 'ALL-01'
  | 'ALL-02'
  | 'ALL-03'
  | 'ALL-03-REJ'
  | 'ALL-04'
  | 'ALL-05'
  | 'ALL-06'
  | 'ALL-07'
  | 'ALL-08'
  | 'ALL-09'
  | 'ALL-10'
  | 'ALL-11'
  | 'ALL-12'
  | 'ALL-13'
  | 'ALL-14'
  | 'ALL-15'
  | 'ALL-16'
  | 'ALL-17'
  | 'ALL-18'
  | 'ALL-19'
  | 'ALL-20'
  | 'ALL-21'
  | 'ALL-22'
  | 'ALL-23'
  | 'ALL-24'
  | 'ALL-25'
  | 'ALL-25-EXT'
  | 'ALL-26'
  | 'ALL-27'
  | 'ALL-28'
  | 'ALL-29'
  | 'ALL-30'
  | 'DRA-01'
  | 'DRA-02'
  | 'DRD-01'
  | 'DRL-01'
  | 'DRG-01'
  | 'GEN-01'
  | 'GEN-02'
  | 'GEN-03'
  | 'GEN-04'
  | 'GEN-05'
  | 'GEN-06'
  | 'GEN-07'
  | 'GEN-08'
  | 'GEN-09'
  | 'GEN-10'
  | 'GEN-11'
  | 'GEN-12'
  | 'GEN-13'
  | 'LOA-01'
  | 'LOA-02'
  | 'LOA-03'
  | 'LOA-04'
  | 'LOA-05'
  | 'LOA-06'
  | 'LOA-07'
  | 'LOA-08'
  | 'LOA-09'
  | 'LOA-10'
  | 'LOA-11'
  | 'LOA-12'
  | 'LOA-13'
  | 'MUL-01'
  | 'MUL-02'
  | 'MUL-03'
  | 'P-01'
  | 'P-02'
  | 'ALT-ALL-29'
  | 'ALT-LOA-13'
  | 'STO-01'
  | 'STO-02'
  | 'STO-03'
  | 'STO-04'
  | 'STO-05'
  | 'STO-06'
  | 'PRC-01'
  | 'PRC-02'
  | 'PRC-03'
  | 'PRC-04'
  | 'PRC-05';
/**
 * HTTP methods and descriptions
 *
 * Methods from the following RFCs are all observed:
 *
 *     * RFC 7231: Hypertext Transfer Protocol (HTTP/1.1), obsoletes 2616
 *     * RFC 5789: PATCH Method for HTTP
 */
export type HTTPMethod = 'CONNECT' | 'DELETE' | 'GET' | 'HEAD' | 'OPTIONS' | 'PATCH' | 'POST' | 'PUT' | 'TRACE';
/**
 * HTTP status codes and reason phrases
 *
 * Status codes from the following RFCs are all observed:
 *
 *     * RFC 7231: Hypertext Transfer Protocol (HTTP/1.1), obsoletes 2616
 *     * RFC 6585: Additional HTTP Status Codes
 *     * RFC 3229: Delta encoding in HTTP
 *     * RFC 4918: HTTP Extensions for WebDAV, obsoletes 2518
 *     * RFC 5842: Binding Extensions to WebDAV
 *     * RFC 7238: Permanent Redirect
 *     * RFC 2295: Transparent Content Negotiation in HTTP
 *     * RFC 2774: An HTTP Extension Framework
 *     * RFC 7725: An HTTP Status Code to Report Legal Obstacles
 *     * RFC 7540: Hypertext Transfer Protocol Version 2 (HTTP/2)
 *     * RFC 2324: Hyper Text Coffee Pot Control Protocol (HTCPCP/1.0)
 *     * RFC 8297: An HTTP Status Code for Indicating Hints
 *     * RFC 8470: Using Early Data in HTTP
 */
export type HTTPStatus =
  | 100
  | 101
  | 102
  | 103
  | 200
  | 201
  | 202
  | 203
  | 204
  | 205
  | 206
  | 207
  | 208
  | 226
  | 300
  | 301
  | 302
  | 303
  | 304
  | 305
  | 307
  | 308
  | 400
  | 401
  | 402
  | 403
  | 404
  | 405
  | 406
  | 407
  | 408
  | 409
  | 410
  | 411
  | 412
  | 413
  | 414
  | 415
  | 416
  | 417
  | 418
  | 421
  | 422
  | 423
  | 424
  | 425
  | 426
  | 428
  | 429
  | 431
  | 451
  | 500
  | 501
  | 502
  | 503
  | 504
  | 505
  | 506
  | 507
  | 508
  | 510
  | 511;

export interface AdminComplianceRequestResponse {
  classes: string[];
  compliance_request_id: number;
  created_at: string;
  created_by: number;
  created_by_user: ComplianceRequestUser;
  csip_aus_version: string;
  der_brand: string;
  der_oem: string;
  der_representative_models: string;
  der_series: string;
  onsite_hardware_details: string;
  runs: number[];
  software_client_providers: string;
  software_client_type: string;
  software_client_versions: string;
  status: number;
  updated_at: string;
  updated_by: number;
  updated_by_user: ComplianceRequestUser;
  witnessed_at: string;
}
export interface ComplianceRequestUser {
  issuer_id: string;
  subject_id: string;
  user_id: number;
  user_name: string | null;
}
/**
 * GET /api/admin/compliance/requests — all compliance requests, with submitter info.
 */
export interface AdminComplianceRequestsResponse {
  requests: AdminComplianceRequestResponse[];
}
/**
 * GET /api/admin/stats — the schema's AdminStatsResponse reshaped for the dashboard
 * (dict counters turned into ordered lists, `max_run_id` surfaced as `max_run_number`).
 */
export interface AdminStatsResponse {
  max_run_number: number;
  procedures: ProcedureStat[];
  runs_per_week: WeekBar[];
  total_failed: number;
  total_passed: number;
  total_run_groups: number;
  total_runs: number;
  total_users: number;
  user_leaderboard: UserLeaderboardEntry[];
  version_counts: {
    [k: string]: number;
  };
}
export interface ProcedureStat {
  classes: string[] | null;
  failed: number;
  latest_failed: number;
  latest_passed: number;
  passed: number;
  test_procedure_id: string;
  total_runs: number;
}
/**
 * A weekly runs-per-week bar; month/year blanked when same as the previous bar.
 */
export interface WeekBar {
  count: number;
  month: string;
  year: string;
}
export interface UserLeaderboardEntry {
  name: string;
  run_count: number;
}
/**
 * One user with their run groups, plus a search blob the admin table filters on.
 */
export interface AdminUserResponse {
  matchable_description: string;
  name: string | null;
  run_groups: RunGroupResponse[];
  subject_id: string;
  user_id: number;
}
export interface RunGroupResponse {
  certificate_created_at: string | null;
  certificate_id: number | null;
  created_at: string;
  csip_aus_version: string;
  is_device_cert: boolean | null;
  is_static_uri: boolean;
  name: string;
  run_group_id: number;
  static_uri: string | null;
  total_runs: number;
}
/**
 * GET /api/admin/users.
 */
export interface AdminUsersResponse {
  users: AdminUserResponse[];
}
/**
 * Represents the various CSIP-Aus versions available for testing
 */
export interface CSIPAusVersionResponse {
  version: string;
}
export interface ClientInteraction {
  interaction_type: ClientInteractionType;
  timestamp: string;
}
export interface ComplianceClass {
  description: string;
  name: string;
}
export interface ComplianceClassEntry {
  class_details: ComplianceClass;
  class_name: string;
  compliant: boolean;
  per_run_status: PerRunStatus[];
}
export interface PerRunStatus {
  description: string;
  latest_run_id: number | null;
  status: ComplianceStatus;
  test_procedure_id: string;
}
/**
 * GET /api/compliance/form-data — everything the request wizard needs to render.
 *
 * Consolidates what the old template passed as several base64 blobs: the selectable CSIP-Aus
 * versions, every compliance class (with its description), the version→class→test-procedure
 * map used to filter classes and compute missing runs, the test procedures the user has a
 * successful run for, and those successful runs (for the per-procedure run selectors).
 */
export interface ComplianceFormDataResponse {
  completed_test_procedures: string[];
  compliance_classes: ComplianceClass[];
  csipaus_versions: string[];
  successful_runs: RunResponse[];
  tests_by_version_and_class: {
    [k: string]: {
      [k: string]: string[];
    };
  };
}
export interface RunResponse {
  all_criteria_met: boolean | null;
  classes: string[] | null;
  created_at: string;
  finalised_at: string | null;
  has_artifacts: boolean;
  is_device_cert: boolean;
  playlist_execution_id: string | null;
  playlist_order: number | null;
  playlist_runs: PlaylistRunInfo[] | null;
  run_id: number;
  status: RunStatusResponse;
  test_procedure_id: string;
  test_url: string;
}
/**
 * Summary info for a run within a playlist
 */
export interface PlaylistRunInfo {
  run_id: number;
  status: RunStatusResponse;
  test_procedure_id: string;
}
export interface ComplianceRequestResponse {
  classes: string[];
  compliance_request_id: number;
  created_at: string;
  created_by: number;
  csip_aus_version: string;
  der_brand: string;
  der_oem: string;
  der_representative_models: string;
  der_series: string;
  onsite_hardware_details: string;
  runs: number[];
  software_client_providers: string;
  software_client_type: string;
  software_client_versions: string;
  status: number;
  updated_at: string;
  updated_by: number;
  witnessed_at: string;
}
/**
 * GET /api/compliance/requests — the user's compliance requests (pagination flattened).
 */
export interface ComplianceRequestsResponse {
  requests: ComplianceRequestResponse[];
}
/**
 * GET /api/group/<id>/compliance — compliance-by-class for the run group.
 */
export interface ComplianceResponse {
  compliance_by_class: ComplianceClassEntry[];
}
/**
 * GET /api/config — the user's config plus their run groups and selectable versions.
 */
export interface ConfigResponse {
  config: UserConfig;
  csip_aus_versions: CSIPAusVersionResponse[];
  run_groups: RunGroupResponse[];
}
export interface UserConfig {
  pen: number | null;
  subscription_domain: string;
}
export interface CriteriaEntry {
  details: string;
  success: boolean;
  type: string;
}
/**
 * Snapshot of DERCapability for UI display
 */
export interface DERCapabilityInfo {
  der_type: string | null;
  doe_modes_supported: string[] | null;
  max_a: number | null;
  max_charge_rate_w: number | null;
  max_discharge_rate_w: number | null;
  max_va: number | null;
  max_var: number | null;
  max_var_neg: number | null;
  max_w: number | null;
  max_wh: number | null;
  modes_supported: string[] | null;
}
/**
 * Snapshot of DERSettings for UI display
 */
export interface DERSettingsInfo {
  doe_modes_enabled: string[] | null;
  grad_w: number | null;
  max_charge_rate_w: number | null;
  max_discharge_rate_w: number | null;
  max_va: number | null;
  max_var: number | null;
  max_var_neg: number | null;
  max_w: number | null;
  modes_enabled: string[] | null;
}
/**
 * Snapshot of current DER real-time status (from SiteDERStatus / sep2 DERStatus).
 * Bitmaps/enums resolved to strings.
 */
export interface DERStatusInfo {
  alarm_status: string[] | null;
  generator_connect_status: string[] | null;
  inverter_status: string | null;
  local_control_mode_status: string | null;
  manufacturer_status: string | null;
  operational_mode_status: string | null;
  state_of_charge_status: number | null;
  storage_connect_status: string[] | null;
  storage_mode_status: string | null;
}
export interface DataStreamPoint {
  offset: string;
  watts: number | null;
}
export interface EndDeviceMetadata {
  aggregator_id: number | null;
  der_capability: DERCapabilityInfo | null;
  der_settings: DERSettingsInfo | null;
  der_status: DERStatusInfo | null;
  device_category: number | null;
  doe_modes_enabled: number | null;
  edevid: number | null;
  lfdi: string | null;
  nmi: string | null;
  set_max_w: number | null;
  sfdi: number | null;
  timezone_id: string | null;
}
/**
 * One category's procedure run summaries, in definition order.
 */
export interface GroupedProcedures {
  category: string;
  slug: string;
  summaries: TestProcedureRunSummaryResponse[];
}
export interface TestProcedureRunSummaryResponse {
  category: string;
  classes: string[] | null;
  description: string;
  immediate_start: boolean;
  latest_all_criteria_met: boolean | null;
  latest_run_id: number | null;
  latest_run_status: number | null;
  latest_run_timestamp: string | null;
  run_count: number;
  test_procedure_id: TestProcedureId;
}
/**
 * One playlist execution (active or completed), grouped from its runs.
 */
export interface PlaylistSession {
  created_at: string;
  first_run_id: number;
  is_active: boolean;
  playlist_execution_id: string;
  short_id: string;
  test_statuses: PlaylistTestStatus[];
}
/**
 * One run's status within a playlist session.
 */
export interface PlaylistTestStatus {
  all_criteria_met: boolean | null;
  has_artifacts: boolean;
  run_id: number;
  status: RunStatusResponse;
  test_procedure_id: string;
}
/**
 * One selectable test in the playlist builder.
 */
export interface PlaylistTest {
  classes: string[];
  description: string;
  id: string;
}
/**
 * GET /api/group/<id>/playlist_tests — tests by category plus compliance classes.
 */
export interface PlaylistTestsResponse {
  classes: ComplianceClass[];
  tests_by_category: {
    [k: string]: PlaylistTest[];
  };
}
export interface PreconditionCheckEntry {
  details: string;
  success: boolean;
  type: string;
}
/**
 * GET /api/group/<id>/procedure_summaries — summaries grouped by category plus the
 * compliance-class filter maps the runs table uses.
 */
export interface ProcedureSummariesResponse {
  classes: ComplianceClass[];
  classes_by_category: {
    [k: string]: string[];
  };
  classes_by_test: {
    [k: string]: string[];
  };
  grouped_procedures: GroupedProcedures[];
}
/**
 * GET /api/procedure/<id> — the raw YAML definition for one procedure.
 */
export interface ProcedureYamlResponse {
  test_procedure_id: string;
  yaml: string;
}
/**
 * GET /api/procedures — all test procedures (pagination flattened by the BFF).
 */
export interface ProceduresResponse {
  procedures: TestProcedureResponse[];
}
export interface TestProcedureResponse {
  category: string;
  classes: string[];
  description: string;
  target_versions: string[];
  test_procedure_id: TestProcedureId;
}
export interface ProceedResponse {
  handled: boolean;
}
export interface RequestData {
  request: string | null;
  request_id: number;
  response: string | null;
}
export interface RequestEntry {
  body_xml_errors: string[];
  method: HTTPMethod;
  path: string;
  request_id: number;
  status: HTTPStatus;
  step_name: string;
  timestamp: string;
  url: string;
}
/**
 * The `{run_id}` envelope returned by run/playlist mutations (init/start/finalise/delete).
 */
export interface RunActionResponse {
  run_id: number;
}
/**
 * Run-status page shell: the run plus the few extras the orchestrator doesn't supply.
 *
 * `run` and `playlist_runs` are canonical `RunResponse`s (no reshaping/renaming) — the
 * frontend reads their fields directly and derives playlist order / active-run / next-run
 * itself. The remaining fields are things only the BFF knows or computes.
 */
export interface RunStatusShell {
  is_immediate_start: boolean;
  playlist_name: string | null;
  playlist_runs: RunResponse[] | null;
  run: RunResponse | null;
  run_is_live: boolean;
}
export interface RunnerStatus {
  criteria: CriteriaEntry[];
  csip_aus_version: string;
  end_device_metadata: EndDeviceMetadata | null;
  instructions: string[] | null;
  last_client_interaction: ClientInteraction;
  log_envoy: string;
  precondition_checks: PreconditionCheckEntry[];
  request_history: RequestEntry[];
  status_summary: string;
  step_status: {
    [k: string]: StepEventStatus;
  } | null;
  test_procedure_name: string;
  timeline: TimelineStatus | null;
  timestamp_initialise: string | null;
  timestamp_start: string | null;
  timestamp_status: string;
}
export interface StepEventStatus {
  completed_at: string | null;
  event_status: string | null;
  started_at: string | null;
}
export interface TimelineStatus {
  data_streams: TimelineDataStreamEntry[];
  now_offset: string;
  set_max_w: number | null;
}
export interface TimelineDataStreamEntry {
  dashed: boolean;
  data: DataStreamPoint[];
  label: string;
  stepped: boolean;
}
/**
 * Session/global context for the SPA (GET /api/session).
 */
export interface SessionResponse {
  banner_message: string | null;
  hosted_images: string[];
  permissions: string[];
  support_email: string;
  username: string | null;
  version: string;
}
