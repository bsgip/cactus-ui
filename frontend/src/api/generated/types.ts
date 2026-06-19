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
export type RunStatusResponse = 'initialised' | 'started' | 'finalised' | 'provisioning' | 'skipped';

export interface ClientInteraction {
  interaction_type: ClientInteractionType;
  timestamp: string;
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
 * Summary info for a run within a playlist
 */
export interface PlaylistRunInfo {
  run_id: number;
  status: RunStatusResponse;
  test_procedure_id: string;
}
export interface PreconditionCheckEntry {
  details: string;
  success: boolean;
  type: string;
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
