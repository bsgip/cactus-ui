"""Regenerates the checked-in MSW fixtures from cactus-test-definitions and the Flask
BFF's own serialisers, so the fixtures track shape changes in the same PR that makes
them. Session fixtures (session*.json) are hand-captured from a real login - see
README.md.

Run from the repo root:

    uv run python frontend/fixtures/generate.py
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

# server.py reads these at import time; values are irrelevant for fixture generation
os.environ.setdefault("CACTUS_ORCHESTRATOR_BASEURL", "http://localhost:18080/")
os.environ.setdefault("CACTUS_ORCHESTRATOR_AUDIENCE", "fixture-generation")
os.environ.setdefault("CACTUS_PLATFORM_VERSION", "fixture-generation")
os.environ.setdefault("CACTUS_PLATFORM_SUPPORT_EMAIL", "fixtures@example.com")
os.environ.setdefault("APP_SECRET_KEY", "fixture-generation")

import cactus_schema.orchestrator as schema  # noqa: E402
from cactus_schema.orchestrator.compliance import fetch_compliance_classes  # noqa: E402
from cactus_test_definitions.client import get_all_test_procedures, get_yaml_contents  # noqa: E402

import cactus_ui.server as server  # noqa: E402

FIXTURES_DIR = Path(__file__).parent

# Synthetic run history overlaid on the real procedure list (everything else has no runs)
RUN_STATE = {
    "ALL-01": dict(
        run_count=3,
        latest_all_criteria_met=True,
        latest_run_status=3,
        latest_run_id=120,
        latest_run_timestamp="2026-06-10T03:15:00+00:00",
    ),
    "ALL-02": dict(
        run_count=1,
        latest_all_criteria_met=False,
        latest_run_status=3,
        latest_run_id=118,
        latest_run_timestamp="2026-06-09T23:40:00+00:00",
    ),
    "ALL-03": dict(
        run_count=2,
        latest_all_criteria_met=None,
        latest_run_status=2,
        latest_run_id=123,
        latest_run_timestamp="2026-06-11T01:05:00+00:00",
    ),
}

NO_RUNS = dict(
    run_count=0,
    latest_all_criteria_met=None,
    latest_run_status=None,
    latest_run_id=None,
    latest_run_timestamp=None,
)


def write(name: str, data: dict) -> None:
    with open(FIXTURES_DIR / name, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print(f"wrote {name}")


def single_page(items: list) -> dict:
    return server.paginated_json(
        schema.Pagination(
            total_pages=1,
            total_items=len(items),
            page_size=100,
            current_page=1,
            prev_page=None,
            next_page=None,
            items=items,
        )
    )


def run(
    run_id: int,
    test_procedure_id: str,
    status: schema.RunStatusResponse,
    all_criteria_met: bool | None,
    has_artifacts: bool,
    created_at: str,
    finalised_at: str | None = None,
) -> schema.RunResponse:
    return schema.RunResponse(
        run_id=run_id,
        test_procedure_id=test_procedure_id,
        test_url=f"https://cactus.example/run/{run_id}",
        status=status,
        all_criteria_met=all_criteria_met,
        created_at=created_at,
        finalised_at=finalised_at,
        is_device_cert=True,
        has_artifacts=has_artifacts,
        playlist_execution_id=None,
        playlist_order=None,
        playlist_runs=None,
        classes=["A", "G"],
    )


def main() -> None:
    # procedures.json - the real procedure definitions, as /api/procedures serves them
    procedures = [
        schema.TestProcedureResponse(
            test_procedure_id=tp_id,
            description=tp.description,
            category=tp.category,
            classes=tp.classes or [],
            target_versions=[v.value for v in tp.target_versions],
        )
        for tp_id, tp in get_all_test_procedures().items()
    ]
    write("procedures.json", {"procedures": [p.to_dict() for p in procedures]})

    # procedure_yaml.json - ALL-01's raw YAML, as /api/procedure/<id> serves it
    write("procedure_yaml.json", {"test_procedure_id": "ALL-01", "yaml": get_yaml_contents("ALL-01")})

    # procedure_summaries.json - real procedures + the synthetic run history above
    summaries = [
        schema.TestProcedureRunSummaryResponse(
            test_procedure_id=p.test_procedure_id,
            description=p.description,
            category=p.category,
            classes=p.classes,
            immediate_start=False,
            **RUN_STATE.get(p.test_procedure_id, NO_RUNS),
        )
        for p in procedures
    ]
    write("procedure_summaries.json", server.build_procedure_summaries_json(summaries))

    # run_groups.json - two groups so the group dropdown renders
    write(
        "run_groups.json",
        single_page(
            [
                schema.RunGroupResponse(
                    run_group_id=1,
                    name="Battery Mk1",
                    csip_aus_version="v1.2",
                    created_at="2026-05-01T00:00:00+00:00",
                    is_device_cert=True,
                    certificate_id=11,
                    certificate_created_at="2026-05-01T00:05:00+00:00",
                    total_runs=6,
                ),
                schema.RunGroupResponse(
                    run_group_id=2,
                    name="Battery Mk2",
                    csip_aus_version="v1.3-beta/storage",
                    created_at="2026-06-01T00:00:00+00:00",
                    is_device_cert=False,
                    certificate_id=12,
                    certificate_created_at="2026-06-01T00:05:00+00:00",
                    total_runs=0,
                ),
            ]
        ),
    )

    # procedure_runs.json - ALL-01 runs covering pass/fail/initialised/no-artifacts rows
    status = schema.RunStatusResponse
    write(
        "procedure_runs.json",
        single_page(
            [
                run(
                    120,
                    "ALL-01",
                    status.finalised,
                    True,
                    True,
                    "2026-06-10T03:15:00+00:00",
                    "2026-06-10T04:00:00+00:00",
                ),
                run(
                    117,
                    "ALL-01",
                    status.finalised,
                    False,
                    True,
                    "2026-06-09T22:10:00+00:00",
                    "2026-06-09T22:55:00+00:00",
                ),
                run(110, "ALL-01", status.initialised, None, False, "2026-06-08T10:30:00+00:00"),
                run(
                    104,
                    "ALL-01",
                    status.finalised,
                    None,
                    False,
                    "2026-06-07T08:00:00+00:00",
                    "2026-06-07T09:00:00+00:00",
                ),
            ]
        ),
    )

    # active_runs.json - one started + one initialised run
    write(
        "active_runs.json",
        single_page(
            [
                run(123, "ALL-03", status.started, None, False, "2026-06-11T01:05:00+00:00"),
                run(110, "ALL-01", status.initialised, None, False, "2026-06-08T10:30:00+00:00"),
            ]
        ),
    )

    # compliance.json - computed from the same summaries, as /api/group/<id>/compliance serves it
    write("compliance.json", server.build_compliance_json(summaries))

    # playlist_tests.json - tests-by-category + classes, as /api/group/<id>/playlist_tests serves it
    all_classes: set[str] = set()
    for p in summaries:
        if p.classes:
            all_classes.update(p.classes)
    write(
        "playlist_tests.json",
        {
            "tests_by_category": server.build_playlist_tests_by_category(summaries),
            "classes": [{"name": c.name, "description": c.description} for c in fetch_compliance_classes(all_classes)],
        },
    )

    # playlist_sessions.json - one active + one past session, as /api/group/<id>/playlist_sessions serves it
    def test_status(run_id: int, tp_id: str, st: str, met: bool | None, artifacts: bool) -> dict:
        return {
            "test_procedure_id": tp_id,
            "run_id": run_id,
            "status": st,
            "all_criteria_met": met,
            "has_artifacts": artifacts,
        }

    write(
        "playlist_sessions.json",
        [
            {
                "playlist_execution_id": "active-exec-0001-aaaa",
                "short_id": "active-e",
                "first_run_id": 201,
                "created_at": "2026-06-12T02:00:00+00:00",
                "test_statuses": [
                    test_status(201, "ALL-01", "finalised", True, True),
                    test_status(202, "ALL-02", "started", None, False),
                    test_status(203, "ALL-03", "initialised", None, False),
                ],
                "is_active": True,
            },
            {
                "playlist_execution_id": "past-exec-0002-bbbb",
                "short_id": "past-exe",
                "first_run_id": 150,
                "created_at": "2026-06-10T08:00:00+00:00",
                "test_statuses": [
                    test_status(150, "ALL-01", "finalised", True, True),
                    test_status(151, "ALL-02", "finalised", False, True),
                    test_status(152, "ALL-03", "skipped", None, False),
                ],
                "is_active": False,
            },
        ],
    )


def prettier() -> None:
    """Match the repo's Prettier formatting so regeneration produces minimal diffs."""
    npx = shutil.which("npx")
    if npx is None:
        print("npx not found - run `npx prettier --write fixtures/*.json` from frontend/ yourself")
        return
    subprocess.run([npx, "prettier", "--write", "*.json"], cwd=FIXTURES_DIR, check=True)  # noqa: S603


if __name__ == "__main__":
    main()
    prettier()
