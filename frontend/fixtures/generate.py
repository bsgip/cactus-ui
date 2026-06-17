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

import dataclasses  # noqa: E402

import cactus_schema.orchestrator as schema  # noqa: E402
import cactus_schema.runner.schema as runner_schema  # noqa: E402
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


def check_keys(label: str, data: dict, dc: type) -> None:
    """Guard hand-built fixtures against schema drift: the dict's keys must exactly match
    the dataclass field names (FastAPI serialises these dataclasses with their native
    snake_case field names, which is the wire format the UI consumes)."""
    expected = {f.name for f in dataclasses.fields(dc)}
    actual = set(data)
    if actual != expected:
        raise SystemExit(
            f"{label}: key drift vs {dc.__name__}: "
            f"missing={sorted(expected - actual)} unexpected={sorted(actual - expected)}"
        )


def check_runner_status(label: str, status: dict) -> None:
    """Validate a hand-built RunnerStatus fixture (and its key nested shapes) against the
    cactus_schema.runner.schema dataclasses."""
    r = runner_schema
    check_keys(label, status, r.RunnerStatus)
    check_keys(f"{label}.last_client_interaction", status["last_client_interaction"], r.ClientInteraction)
    for c in status["criteria"]:
        check_keys(f"{label}.criteria[]", c, r.CriteriaEntry)
    for c in status["precondition_checks"]:
        check_keys(f"{label}.precondition_checks[]", c, r.PreconditionCheckEntry)
    for entry in (status["step_status"] or {}).values():
        check_keys(f"{label}.step_status[]", entry, r.StepEventStatus)
    for req in status["request_history"]:
        check_keys(f"{label}.request_history[]", req, r.RequestEntry)
    if status["timeline"] is not None:
        check_keys(f"{label}.timeline", status["timeline"], r.TimelineStatus)
        for ds in status["timeline"]["data_streams"]:
            check_keys(f"{label}.timeline.data_streams[]", ds, r.TimelineDataStreamEntry)
            for point in ds["data"]:
                check_keys(f"{label}.timeline.data_streams[].data[]", point, r.DataStreamPoint)
    edm = status["end_device_metadata"]
    if edm is not None:
        check_keys(f"{label}.end_device_metadata", edm, r.EndDeviceMetadata)
        check_keys(f"{label}.der_capability", edm["der_capability"], r.DERCapabilityInfo)
        check_keys(f"{label}.der_settings", edm["der_settings"], r.DERSettingsInfo)
        check_keys(f"{label}.der_status", edm["der_status"], r.DERStatusInfo)


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

    # --- Run status page (run_status.html port) fixtures ---------------------------------

    # run_status_runner.json - a rich "started" RunnerStatus exercising every live panel:
    # requests (incl. an XSD error + an Unmatched one), steps (resolved/active-proceed/
    # pending), criteria, precondition checks, timeline data, and full DER metadata.
    runner_started = {
        "timestamp_status": "2026-06-17T05:03:00+00:00",
        "timestamp_initialise": "2026-06-17T04:58:00+00:00",
        "timestamp_start": "2026-06-17T05:00:00+00:00",
        "status_summary": "Test in progress - 1 of 3 steps complete",
        "last_client_interaction": {
            "interaction_type": "Request Proxied",
            "timestamp": "2026-06-17T05:02:55+00:00",
        },
        "csip_aus_version": "v1.2",
        "log_envoy": (
            "2026-06-17 05:00:10 INFO envoy GET /edev -> 200\n"
            "2026-06-17 05:01:30 WARN envoy PUT /edev/1/ders/1/dercap -> 400 (schema invalid)\n"
            "2026-06-17 05:02:55 INFO envoy PUT /edev/1/ders/1/ders -> 204"
        ),
        "criteria": [
            {"success": True, "type": "response-contains-edev", "details": "EndDevice was registered"},
            {"success": False, "type": "der-settings-updated", "details": "Awaiting DERSettings update"},
        ],
        "precondition_checks": [
            {"success": True, "type": "edevice-registered", "details": "EndDevice 1 registered"},
            {"success": True, "type": "der-present", "details": "DER discovered on the EndDevice"},
        ],
        "instructions": [
            "Ensure the device is powered on and connected to the utility server",
            "Confirm the inverter is exporting before proceeding",
        ],
        "test_procedure_name": "ALL-01",
        "step_status": {
            "GET-EDEV": {
                "started_at": "2026-06-17T05:00:05+00:00",
                "completed_at": "2026-06-17T05:00:20+00:00",
                "event_status": None,
            },
            "POST-DERSETTINGS": {
                "started_at": "2026-06-17T05:00:25+00:00",
                "completed_at": None,
                "event_status": "Waiting on signal to proceed",
            },
            "POST-DERSTATUS": {"started_at": None, "completed_at": None, "event_status": None},
        },
        "request_history": [
            {
                "url": "https://cactus.example/edev",
                "path": "/edev",
                "method": "GET",
                "status": 200,
                "timestamp": "2026-06-17T05:00:10+00:00",
                "step_name": "GET-EDEV",
                "body_xml_errors": [],
                "request_id": 1,
            },
            {
                "url": "https://cactus.example/edev/1/ders/1/dercap",
                "path": "/edev/1/ders/1/dercap",
                "method": "PUT",
                "status": 400,
                "timestamp": "2026-06-17T05:01:30+00:00",
                "step_name": "POST-DERSETTINGS",
                "body_xml_errors": ["Element 'rtgMaxW': This element is not expected. Expected is ( rtgMaxVA )."],
                "request_id": 2,
            },
            {
                "url": "https://cactus.example/edev/1/ders/1/ders",
                "path": "/edev/1/ders/1/ders",
                "method": "PUT",
                "status": 204,
                "timestamp": "2026-06-17T05:02:55+00:00",
                "step_name": "Unmatched",
                "body_xml_errors": [],
                "request_id": 3,
            },
        ],
        "timeline": {
            "data_streams": [
                {
                    "label": "Active Power",
                    "data": [
                        {"watts": 0, "offset": "0s"},
                        {"watts": 1500, "offset": "0m20s"},
                        {"watts": 3200, "offset": "0m40s"},
                        {"watts": 3200, "offset": "1m0s"},
                    ],
                    "stepped": False,
                    "dashed": False,
                },
                {
                    "label": "Limit",
                    "data": [{"watts": 5000, "offset": "0s"}, {"watts": 5000, "offset": "1m0s"}],
                    "stepped": True,
                    "dashed": True,
                },
            ],
            "set_max_w": 5000,
            "now_offset": "1m0s",
        },
        "end_device_metadata": {
            "edevid": 1,
            "lfdi": "0x48BC3A2F9D14E7B6C0A1",
            "sfdi": 123456789,
            "nmi": "6123456789",
            "aggregator_id": None,
            "set_max_w": 5000,
            "doe_modes_enabled": 3,
            "device_category": 0,
            "timezone_id": "Australia/Brisbane",
            "der_capability": {
                "der_type": "COMBINED_PV_AND_STORAGE",
                "modes_supported": ["OP_MOD_FIXED_W", "OP_MOD_VOLT_VAR"],
                "max_w": 5000,
                "max_va": 5500,
                "max_var": 3000,
                "max_var_neg": 3000,
                "max_a": 22,
                "max_charge_rate_w": 5000,
                "max_discharge_rate_w": 5000,
                "max_wh": 13500,
                "doe_modes_supported": ["OP_MOD_EXPORT_LIMIT_W", "OP_MOD_IMPORT_LIMIT_W"],
            },
            "der_settings": {
                "modes_enabled": ["OP_MOD_FIXED_W"],
                "max_w": 5000,
                "max_va": 5500,
                "max_var": 3000,
                "max_var_neg": 3000,
                "max_charge_rate_w": 5000,
                "max_discharge_rate_w": 5000,
                "grad_w": 100,
                "doe_modes_enabled": ["OP_MOD_EXPORT_LIMIT_W"],
            },
            "der_status": {
                "alarm_status": [],
                "inverter_status": "NORMAL",
                "operational_mode_status": "GRID_FOLLOWING",
                "generator_connect_status": ["CONNECTED"],
                "storage_connect_status": ["CONNECTED"],
                "storage_mode_status": "CHARGING",
                "state_of_charge_status": 62,
                "local_control_mode_status": "REMOTE",
                "manufacturer_status": "OK",
            },
        },
    }
    check_runner_status("run_status_runner.json", runner_started)
    write("run_status_runner.json", runner_started)

    # run_status_runner_initialised.json - the pre-start phase: instructions present, no
    # timestamp_start, no steps/timeline/device yet.
    runner_initialised = {
        "timestamp_status": "2026-06-17T04:59:00+00:00",
        "timestamp_initialise": "2026-06-17T04:58:00+00:00",
        "timestamp_start": None,
        "status_summary": "Awaiting start",
        "last_client_interaction": {
            "interaction_type": "Test Procedure Initialised",
            "timestamp": "2026-06-17T04:58:00+00:00",
        },
        "csip_aus_version": "v1.2",
        "log_envoy": "No logs recorded",
        "criteria": [],
        "precondition_checks": [
            {"success": True, "type": "edevice-registered", "details": "EndDevice 1 registered"},
        ],
        "instructions": ["Ensure the device is powered on before starting the test"],
        "test_procedure_name": "ALL-01",
        "step_status": None,
        "request_history": [],
        "timeline": None,
        "end_device_metadata": None,
    }
    check_runner_status("run_status_runner_initialised.json", runner_initialised)
    write("run_status_runner_initialised.json", runner_initialised)

    # run_status_shell*.json - the page shell (_build_run_status_shell output). One live
    # standalone run, one finalised, one live run inside a playlist.
    write(
        "run_status_shell.json",
        {
            "run_id": 123,
            "run_is_live": True,
            "run_status": "started",
            "run_test_uri": "https://cactus.example/run/123",
            "run_procedure_id": "ALL-01",
            "run_has_artifacts": False,
            "is_witness_test": False,
            "playlist_info": None,
            "next_playlist_run_id": None,
            "current_active_run": None,
        },
    )
    write(
        "run_status_shell_finalised.json",
        {
            "run_id": 120,
            "run_is_live": False,
            "run_status": "finalised",
            "run_test_uri": "https://cactus.example/run/120",
            "run_procedure_id": "ALL-01",
            "run_has_artifacts": True,
            "is_witness_test": False,
            "playlist_info": None,
            "next_playlist_run_id": None,
            "current_active_run": None,
        },
    )
    write(
        "run_status_shell_playlist.json",
        {
            "run_id": 202,
            "run_is_live": True,
            "run_status": "started",
            "run_test_uri": "https://cactus.example/run/202",
            "run_procedure_id": "ALL-02",
            "run_has_artifacts": False,
            "is_witness_test": False,
            "playlist_info": {
                "name": "Smoke Test Playlist",
                "started_at": "2026-06-17T04:58:00+00:00",
                "current_order": 1,
                "total": 3,
                "runs": [
                    {
                        "test_procedure_id": "ALL-01",
                        "run_id": 201,
                        "status": "finalised",
                        "all_criteria_met": True,
                        "has_artifacts": True,
                    },
                    {
                        "test_procedure_id": "ALL-02",
                        "run_id": 202,
                        "status": "started",
                        "all_criteria_met": None,
                        "has_artifacts": False,
                    },
                    {
                        "test_procedure_id": "ALL-03",
                        "run_id": 203,
                        "status": "initialised",
                        "all_criteria_met": None,
                        "has_artifacts": False,
                    },
                ],
            },
            "next_playlist_run_id": 203,
            "current_active_run": {"run_id": 202, "test_procedure_id": "ALL-02", "order": 1},
        },
    )

    # run_request_details.json - raw request/response for the request-details modal
    write(
        "run_request_details.json",
        {
            "request_id": 2,
            "request": (
                "PUT /edev/1/ders/1/dercap HTTP/1.1\nHost: cactus.example\n"
                "Content-Type: application/sep+xml\n\n"
                '<DERCapability xmlns="urn:ieee:std:2030.5:ns"><rtgMaxW value="5000"/></DERCapability>'
            ),
            "response": (
                "HTTP/1.1 400 Bad Request\nContent-Type: application/sep+xml\n\n"
                '<Error xmlns="urn:ieee:std:2030.5:ns"><message>Element rtgMaxW is not expected</message></Error>'
            ),
        },
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
