from datetime import UTC, datetime, timedelta
from enum import IntEnum, auto

import requests
from cactus_schema import orchestrator


class ComplianceRequestStatus(IntEnum):
    """Encodes the status of a compliance request

    submitted    - client has created the request
                   admin has ability to open the request (see under_review)
                   client has ability to edit request
    under_review - once an admin opens a previously submitted request its status changes to 'under review'
                   admin has ability to edit the request
                   client can no longer edit the request
    pushed_back  - admin has pushed the request back to the client (changes needed)
                   admin can no longer edit the request
                   client has ability to edit the request
    finalised    - the compliance request is finalised (a compliance record gets created)
                   neither admin nor client can modify the request
    """

    SUBMITTED = auto()
    UNDER_REVIEW = auto()
    PUSHED_BACK = auto()
    FINALISED = auto()


def generate_mock_responses() -> dict[str, list[requests.Request]]:
    """Returns a dictionary of placeholder responses for testing compliance request functionality

    result["mock_fetch_compliance_requests"] is a stand-in for calling `orchestrator.fetch_compliance_requests`.
    result["mock_fetch_compliance_request"] is a stand-in for calling `orchestrator.fetch_compliance_request`.
    result["mock_fetch_ordered_successful_runs"] is a stand-in for calling `orchestrator.fetch_ordered_successful_runs`.

    The ordered successful runs has been carefully chosen to cover the following compliance cases:
    - A, DR-A, C, S-L, S-G, DER-A, G, DER-G, L, DER-L, M, PRC? — All incomplete with not test runs

    - DR-L Complete and some failed (DRA-02 ✓, DRL-01 ✕)
    - DR-G Incomplete (DRA-02 ✓, DRG-01a ∄)
    - DR-D Complete and all pass (DRD-01 ✓)
    - M Complete and all passed (MUL-01 ✓, MUL-02 ✓, MUL-03 ✓)

    In the case of the MUL-XX, each procedure has two runs however:
    - MUL-01 both passed
    - MUL-02 fail, then pass (i.e. most recent passed)
    - MUL-03 pass, then fail (i.e. most recent failed)
    """
    result = {}

    common_values = {
        "created_by": 1,
        "updated_by": 1,
        "classes": {"A", "L", "DER-A"},
        "runs": {1, 2, 3},
        "csip_aus_version": "v1.2",
        "witnessed_at": datetime.now(UTC) - timedelta(weeks=4),
        "der_brand": "placeholder-brand",
        "der_oem": "placeholder-oem",
        "der_series": "placeholder-series1, placeholder-series2",
        "der_representative_models": "placeholder-model-X, placeholder-model-Y",
        "software_client_type": "proxy",
        "software_client_providers": "placeholder-software-provider",
        "software_client_versions": "placeholder-software-version",
        "onsite_hardware_details": "placeholder-hardware-details",
    }

    # mock fetch compliance requests
    compliance_requests = [
        orchestrator.ComplianceRequestResponse(
            compliance_request_id=1,
            created_at=datetime.now(UTC) - timedelta(weeks=3),
            updated_at=datetime.now(UTC) - timedelta(weeks=3),
            status=ComplianceRequestStatus.FINALISED,
            **common_values,
        ),
        orchestrator.ComplianceRequestResponse(
            compliance_request_id=3,
            created_at=datetime.now(UTC) - timedelta(weeks=2),
            updated_at=datetime.now(UTC) - timedelta(weeks=2),
            status=ComplianceRequestStatus.FINALISED,
            **common_values,
        ),
        orchestrator.ComplianceRequestResponse(
            compliance_request_id=45,
            created_at=datetime.now(UTC) - timedelta(days=3),
            updated_at=datetime.now(UTC) - timedelta(days=3),
            status=ComplianceRequestStatus.PUSHED_BACK,
            **common_values,
        ),
        orchestrator.ComplianceRequestResponse(
            compliance_request_id=72,
            created_at=datetime.now(UTC) - timedelta(hours=2),
            updated_at=datetime.now(UTC) - timedelta(hours=2),
            status=ComplianceRequestStatus.UNDER_REVIEW,
            **common_values,
        ),
        orchestrator.ComplianceRequestResponse(
            compliance_request_id=73,
            created_at=datetime.now(UTC) - timedelta(hours=1),
            updated_at=datetime.now(UTC) - timedelta(hours=1),
            status=ComplianceRequestStatus.SUBMITTED,
            **common_values,
        ),
    ]
    result["mock_fetch_compliance_requests"] = compliance_requests

    # mock fetch compliance request
    result["mock_fetch_compliance_request"] = compliance_requests[0]

    # mock fetch ordered successful runs
    runs = []
    for test_procedure, passed, run_id in [
        ("DRA-02", True, 1),
        ("DRL-01", False, 2),
        ("DRA-02", True, 3),
        ("DRD-01", True, 4),
        ("MUL-01", True, 5),
        ("MUL-01", True, 6),
        ("MUL-02", False, 7),
        ("MUL-02", True, 8),
        ("MUL-03", True, 9),
        ("MUL-03", False, 10),
    ]:
        # Only include successful runs
        if not passed:
            continue
        base_time = datetime.now(UTC) - timedelta(weeks=10)
        created_delta = timedelta(days=run_id)
        finalised_delta = timedelta(days=run_id + 1)
        runs.append(
            orchestrator.RunResponse(
                run_id=run_id,
                test_procedure_id=test_procedure,
                test_url="",
                status=orchestrator.RunStatusResponse.finalised,
                all_criteria_met=passed,
                created_at=base_time + created_delta,
                finalised_at=base_time + finalised_delta,
                is_device_cert=True,
                has_artifacts=True,
                playlist_execution_id=None,
                playlist_order=None,
                playlist_runs=None,
            )
        )
    result["mock_fetch_ordered_successful_runs"] = runs

    return result


mock_responses = generate_mock_responses()
