"""Guard that the checked-in frontend fixtures still match the Python wire contract.

The fixtures under frontend/fixtures/ are recorded JSON responses that MSW serves to the
Vitest/Playwright suites. They must stay in sync with the dataclasses that define the /api
shapes — otherwise the frontend tests pass against stale data. Validating each fixture
through pydantic catches drift (renamed/removed/retyped fields) at the source.

This is the third leg of the type pipeline: schema export feeds the generated TS types, and
this test ties the fixtures to the same dataclasses (see frontend/fixtures/generate.py).
"""

import json
from pathlib import Path

import pytest
from cactus_schema.orchestrator.schema import Pagination, RunGroupResponse, RunResponse
from cactus_schema.runner.schema import RequestData, RunnerStatus
from pydantic import TypeAdapter

from cactus_ui.api_models import (
    AdminStatsResponse,
    AdminUsersResponse,
    ComplianceResponse,
    ConfigResponse,
    PlaylistSession,
    PlaylistTestsResponse,
    ProceduresResponse,
    ProcedureSummariesResponse,
    ProcedureYamlResponse,
    RunStatusShell,
    SessionResponse,
)

FIXTURES_DIR = Path(__file__).resolve().parents[3] / "frontend" / "fixtures"

# (fixture filename, type the /api endpoint serialises). Covers every fixture tied to a
# dataclass — both the generate.py-produced ones and the hand-captured session*/admin_stats
# fixtures. Only session_unauthenticated.json is excluded: it's the 401 error envelope, not a
# serialised dataclass (see UnauthenticatedResponse in frontend/src/api/types.ts).
FIXTURE_MODELS = [
    ("procedures.json", ProceduresResponse),
    ("procedure_yaml.json", ProcedureYamlResponse),
    ("procedure_summaries.json", ProcedureSummariesResponse),
    ("compliance.json", ComplianceResponse),
    ("playlist_tests.json", PlaylistTestsResponse),
    ("playlist_sessions.json", list[PlaylistSession]),
    ("run_groups.json", Pagination[RunGroupResponse]),
    ("procedure_runs.json", Pagination[RunResponse]),
    ("active_runs.json", Pagination[RunResponse]),
    ("config.json", ConfigResponse),
    ("admin_users.json", AdminUsersResponse),
    ("admin_stats.json", AdminStatsResponse),
    ("session.json", SessionResponse),
    ("session_admin.json", SessionResponse),
    ("run_status_shell.json", RunStatusShell),
    ("run_status_shell_finalised.json", RunStatusShell),
    ("run_status_shell_playlist.json", RunStatusShell),
    ("run_status_runner.json", RunnerStatus),
    ("run_status_runner_initialised.json", RunnerStatus),
    ("run_request_details.json", RequestData),
]


@pytest.mark.parametrize(("filename", "model"), FIXTURE_MODELS)
def test_fixture_matches_schema(filename: str, model: type) -> None:
    data = json.loads((FIXTURES_DIR / filename).read_text())
    # Raises pydantic.ValidationError if the fixture has drifted from the dataclass.
    TypeAdapter(model).validate_python(data)
