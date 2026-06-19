"""Guard that the checked-in frontend fixtures still match the Python wire contract.

The fixtures under frontend/fixtures/ are recorded JSON responses that MSW serves to the
Vitest/Playwright suites. They must stay in sync with the dataclasses that define the /api
shapes — otherwise the frontend tests pass against stale data. Validating each fixture
through pydantic catches drift (renamed/removed/retyped fields) at the source.

This is the third leg of the type pipeline: schema export feeds the generated TS types, and
this test ties the fixtures to the same dataclasses.
"""

import json
from pathlib import Path

import pytest
from cactus_schema.runner.schema import RequestData, RunnerStatus
from pydantic import TypeAdapter

from cactus_ui.api_models import RunStatusShell

FIXTURES_DIR = Path(__file__).resolve().parents[3] / "frontend" / "fixtures"

# (fixture filename, model that the /api endpoint serialises)
FIXTURE_MODELS = [
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
