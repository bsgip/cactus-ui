"""Typed shapes for the BFF-assembled `/api` JSON responses — the single source of truth.

Every `/api` response is one of these dataclasses. The thin pass-through responses embed the
canonical `cactus_schema` types directly (no reshaping/renaming); the rest are genuinely
BFF-owned shapes that join, rename, or derive fields the orchestrator doesn't provide.

`server.py`/`presenters.py` construct and `.to_dict()` these (so the wire format can't drift
from the type), and `scripts/export_api_schema.py` reads them to generate the frontend's
TypeScript. Edit a dataclass here and regenerate; never hand-edit the generated TS.

The one wire shape NOT defined here is `Pagination<T>` — a generic envelope that codegen can't
express cleanly, kept as a small hand-written generic in the frontend's `api/types.ts`.
"""

from dataclasses import dataclass
from enum import StrEnum, auto

from cactus_schema.orchestrator.compliance import ComplianceClass
from cactus_schema.orchestrator.schema import (
    AdminComplianceRequestResponse,
    ComplianceRequestResponse,
    CSIPAusVersionResponse,
    FastAPICompatibleWizard,
    RunGroupResponse,
    RunResponse,
    RunStatusResponse,
    TestProcedureResponse,
    TestProcedureRunSummaryResponse,
)


@dataclass
class SessionResponse(FastAPICompatibleWizard):
    """Session/global context for the SPA (GET /api/session)."""

    username: str | None
    permissions: list[str]
    version: str
    support_email: str
    banner_message: str | None
    hosted_images: list[str]


@dataclass
class ProceduresResponse(FastAPICompatibleWizard):
    """GET /api/procedures — all test procedures (pagination flattened by the BFF)."""

    procedures: list[TestProcedureResponse]


@dataclass
class ProcedureYamlResponse(FastAPICompatibleWizard):
    """GET /api/procedure/<id> — the raw YAML definition for one procedure."""

    test_procedure_id: str
    yaml: str


@dataclass
class RunActionResponse(FastAPICompatibleWizard):
    """The `{run_id}` envelope returned by run/playlist mutations (init/start/finalise/delete)."""

    run_id: int


@dataclass
class GroupedProcedures(FastAPICompatibleWizard):
    """One category's procedure run summaries, in definition order."""

    slug: str
    category: str
    summaries: list[TestProcedureRunSummaryResponse]


@dataclass
class ProcedureSummariesResponse(FastAPICompatibleWizard):
    """GET /api/group/<id>/procedure_summaries — summaries grouped by category plus the
    compliance-class filter maps the runs table uses."""

    grouped_procedures: list[GroupedProcedures]
    classes: list[ComplianceClass]
    classes_by_test: dict[str, list[str]]
    classes_by_category: dict[str, list[str]]


class ComplianceStatus(StrEnum):
    """Per-test compliance state derived from its latest run (compliance page)."""

    active = auto()
    failed = auto()
    success = auto()
    runless = auto()
    unknown = auto()


@dataclass
class PerRunStatus(FastAPICompatibleWizard):
    test_procedure_id: str
    description: str
    latest_run_id: int | None
    status: ComplianceStatus


@dataclass
class ComplianceClassEntry(FastAPICompatibleWizard):
    class_name: str
    class_details: ComplianceClass
    compliant: bool
    per_run_status: list[PerRunStatus]


@dataclass
class ComplianceResponse(FastAPICompatibleWizard):
    """GET /api/group/<id>/compliance — compliance-by-class for the run group."""

    compliance_by_class: list[ComplianceClassEntry]


@dataclass
class ComplianceRequestsResponse(FastAPICompatibleWizard):
    """GET /api/compliance/requests — the user's compliance requests (pagination flattened)."""

    requests: list[ComplianceRequestResponse]


@dataclass
class AdminComplianceRequestsResponse(FastAPICompatibleWizard):
    """GET /api/admin/compliance/requests — all compliance requests, with submitter info."""

    requests: list[AdminComplianceRequestResponse]


@dataclass
class ComplianceFormDataResponse(FastAPICompatibleWizard):
    """GET /api/compliance/form-data — everything the request wizard needs to render.

    Consolidates what the old template passed as several base64 blobs: the selectable CSIP-Aus
    versions, every compliance class (with its description), the version→class→test-procedure
    map used to filter classes and compute missing runs, the test procedures the user has a
    successful run for, and those successful runs (for the per-procedure run selectors).
    """

    csipaus_versions: list[str]
    compliance_classes: list[ComplianceClass]
    tests_by_version_and_class: dict[str, dict[str, list[str]]]
    completed_test_procedures: list[str]
    successful_runs: list[RunResponse]


@dataclass
class UserConfig(FastAPICompatibleWizard):
    subscription_domain: str
    pen: int | None  # None when pen == 0 (reserved; the SPA shows a placeholder)


@dataclass
class ConfigResponse(FastAPICompatibleWizard):
    """GET /api/config — the user's config plus their run groups and selectable versions."""

    config: UserConfig
    run_groups: list[RunGroupResponse]
    csip_aus_versions: list[CSIPAusVersionResponse]


@dataclass
class AdminUserResponse(FastAPICompatibleWizard):
    """One user with their run groups, plus a search blob the admin table filters on."""

    user_id: int
    subject_id: str
    name: str | None
    run_groups: list[RunGroupResponse]
    matchable_description: str


@dataclass
class AdminUsersResponse(FastAPICompatibleWizard):
    """GET /api/admin/users."""

    users: list[AdminUserResponse]


@dataclass
class UserLeaderboardEntry(FastAPICompatibleWizard):
    name: str
    run_count: int


@dataclass
class ProcedureStat(FastAPICompatibleWizard):
    test_procedure_id: str
    classes: list[str] | None
    total_runs: int
    passed: int
    failed: int
    latest_passed: int
    latest_failed: int


@dataclass
class WeekBar(FastAPICompatibleWizard):
    """A weekly runs-per-week bar; month/year blanked when same as the previous bar."""

    month: str
    year: str
    count: int


@dataclass
class AdminStatsResponse(FastAPICompatibleWizard):
    """GET /api/admin/stats — the schema's AdminStatsResponse reshaped for the dashboard
    (dict counters turned into ordered lists, `max_run_id` surfaced as `max_run_number`)."""

    total_users: int
    total_run_groups: int
    total_runs: int
    total_passed: int
    total_failed: int
    max_run_number: int
    version_counts: dict[str, int]
    user_leaderboard: list[UserLeaderboardEntry]
    procedures: list[ProcedureStat]
    runs_per_week: list[WeekBar]


@dataclass
class PlaylistTest(FastAPICompatibleWizard):
    """One selectable test in the playlist builder."""

    id: str
    description: str
    classes: list[str]


@dataclass
class PlaylistTestsResponse(FastAPICompatibleWizard):
    """GET /api/group/<id>/playlist_tests — tests by category plus compliance classes."""

    tests_by_category: dict[str, list[PlaylistTest]]
    classes: list[ComplianceClass]


@dataclass
class PlaylistTestStatus(FastAPICompatibleWizard):
    """One run's status within a playlist session."""

    test_procedure_id: str
    run_id: int
    status: RunStatusResponse
    all_criteria_met: bool | None
    has_artifacts: bool


@dataclass
class PlaylistSession(FastAPICompatibleWizard):
    """One playlist execution (active or completed), grouped from its runs."""

    playlist_execution_id: str
    short_id: str
    first_run_id: int
    created_at: str
    test_statuses: list[PlaylistTestStatus]
    is_active: bool


@dataclass
class RunStatusShell(FastAPICompatibleWizard):
    """Run-status page shell: the run plus the few extras the orchestrator doesn't supply.

    `run` and `playlist_runs` are canonical `RunResponse`s (no reshaping/renaming) — the
    frontend reads their fields directly and derives playlist order / active-run / next-run
    itself. The remaining fields are things only the BFF knows or computes.
    """

    run: RunResponse | None  # the run, forwarded as-is
    run_is_live: bool  # derived: a runner status exists, or status is provisioning/started
    playlist_name: str | None  # playlist display name (from the Flask session; not on any run)
    playlist_runs: list[RunResponse] | None  # all runs in the playlist, fetched and joined
