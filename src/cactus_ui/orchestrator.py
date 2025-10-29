import logging
from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum, auto
from http import HTTPStatus
from os import environ as env
from typing import Any, Callable, Generic, TypeVar

import requests
from dotenv import find_dotenv, load_dotenv

logger = logging.getLogger(__name__)

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

# envvars
CACTUS_ORCHESTRATOR_BASEURL = env["CACTUS_ORCHESTRATOR_BASEURL"]
CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT = int(env.get("CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT", "30"))
CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_SPAWN = int(env.get("CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_SPAWN", "120"))


@dataclass
class RunResponse:
    """Ideally this would be defined in a shared cactus-schema but that doesn't exist. Instead, ensure this remains
    in sync with cactus-orchestrator.schema.RunResponse"""

    run_id: int
    test_procedure_id: str
    test_url: str
    status: str
    all_criteria_met: bool | None
    created_at: datetime
    finalised_at: datetime | None
    is_device_cert: bool


@dataclass
class UserResponse:
    """Ideally this would be defined in a shared cactus-schema but that doesn't exist. Instead, ensure this remains
    in sync with cactus-orchestrator.schema.Procedure"""

    user_id: int
    name: str
    run_groups: list[int]


@dataclass
class ProcedureResponse:
    """Ideally this would be defined in a shared cactus-schema but that doesn't exist. Instead, ensure this remains
    in sync with cactus-orchestrator.schema.Procedure"""

    test_procedure_id: str
    description: str
    category: str
    classes: list[str]


@dataclass
class ConfigResponse:
    """Ideally this would be defined in a shared cactus-schema but that doesn't exist. Instead, ensure this remains
    in sync with cactus-orchestrator.schema.ConfigResponse"""

    subscription_domain: str
    is_static_uri: bool
    static_uri: str | None
    is_device_cert: bool  # if true - all test instances will spawn using the device certificate. Otherwise use agg cert
    aggregator_certificate_expiry: datetime | None  # When the current user aggregator cert expires. None = expired
    device_certificate_expiry: datetime | None  # When the current user device cert expires. None = expired
    pen: int | None


@dataclass
class ProcedureRunSummaryResponse:
    """Ideally this would be defined in a shared cactus-schema but that doesn't exist. Instead, ensure this remains
    in sync with cactus-orchestrator.schema.TestProcedureRunSummaryResponse"""

    test_procedure_id: str
    description: str
    category: str
    classes: list[str] | None
    run_count: int  # Count of runs for this test procedure
    latest_all_criteria_met: bool | None  # Value for all_criteria_met of the most recent Run


@dataclass
class CSIPAusVersionResponse:
    """Ideally this would be defined in a shared cactus-schema but that doesn't exist. Instead, ensure this remains
    in sync with cactus-orchestrator.schema.CSIPAusVersionResponse"""

    version: str  # Derived from the cactus_test_definitions.CSIPAusVersion enum


@dataclass
class RunGroupRequest:
    """Ideally this would be defined in a shared cactus-schema but that doesn't exist. Instead, ensure this remains
    in sync with cactus-orchestrator.schema.RunGroupRequest"""

    csip_aus_version: str


@dataclass
class RunGroupResponse:
    """Ideally this would be defined in a shared cactus-schema but that doesn't exist. Instead, ensure this remains
    in sync with cactus-orchestrator.schema.RunGroupResponse"""

    run_group_id: int
    name: str
    csip_aus_version: str
    created_at: datetime
    total_runs: int


@dataclass
class StartResult:
    success: bool
    error_message: str | None


PaginatedType = TypeVar("PaginatedType")


@dataclass
class Pagination(Generic[PaginatedType]):
    total_pages: int
    total_items: int
    page_size: int
    current_page: int
    prev_page: int | None
    next_page: int | None

    items: list[PaginatedType]


def handle_pagination(paginated_json: dict, item_parser: Callable[[dict], PaginatedType]) -> Pagination[PaginatedType]:
    total_pages = paginated_json.get("pages", 1)
    current_page = paginated_json.get("page", 1)
    if current_page == 1:
        prev_page = None
    else:
        prev_page = current_page - 1

    if current_page < total_pages:
        next_page = current_page + 1
    else:
        next_page = None

    return Pagination(
        total_pages=total_pages,
        total_items=paginated_json.get("total", 0),
        page_size=paginated_json.get("size", 10),
        current_page=current_page,
        prev_page=prev_page,
        next_page=next_page,
        items=[item_parser(i) for i in paginated_json.get("items", [])],
    )


def generate_headers(access_token: str) -> dict[str, Any]:
    return {"Authorization": "Bearer " + access_token}


def safe_request(
    method: str, url: str, headers: dict, timeout: int, json: Any | None = None
) -> requests.Response | None:
    """Unified method for making requests that ensures they log / handle exceptions"""
    try:
        response = requests.request(method=method, url=url, headers=headers, timeout=timeout, json=json)
        logger.info(f"{method} {url} {json} returned HTTP {response}")
        return response
    except Exception as exc:
        logger.error(f"Exception requesting {method} {url}", exc_info=exc)
        return None


def is_success_response(response: requests.Response) -> bool:
    return response.status_code >= 200 and response.status_code < 300


def generate_uri(path: str) -> str:
    """Generates a URI pointing to path at the orchestrator base url"""
    if len(path) == 0:
        return CACTUS_ORCHESTRATOR_BASEURL
    elif path[0] == "/":
        return CACTUS_ORCHESTRATOR_BASEURL.rstrip("/") + path
    else:
        return CACTUS_ORCHESTRATOR_BASEURL.rstrip("/") + "/" + path


def fetch_procedures(access_token: str, page: int) -> Pagination[ProcedureResponse] | None:
    """Fetch the list of test procedures for the dropdown"""
    uri = generate_uri(f"/procedure?page={page}")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return handle_pagination(
        response.json(),
        lambda i: ProcedureResponse(
            test_procedure_id=i["test_procedure_id"],
            description=i["description"],
            category=i["category"],
            classes=i.get("classes", []),
        ),
    )


def fetch_config(access_token: str) -> ConfigResponse | None:
    """Fetch the current config"""
    uri = generate_uri("/config")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    data: dict = response.json()
    return ConfigResponse(
        subscription_domain=data["subscription_domain"],
        is_static_uri=data["is_static_uri"],
        static_uri=data.get("static_uri", None),
        is_device_cert=data["is_device_cert"],
        device_certificate_expiry=data["device_certificate_expiry"],
        aggregator_certificate_expiry=data["aggregator_certificate_expiry"],
        pen=data["pen"] if "pen" in data else 0,
    )


def update_config(
    access_token: str,
    subscription_domain: str | None = None,
    is_static_uri: bool | None = None,
    is_device_cert: bool | None = None,
    pen: int | None = None,
) -> bool:
    """Update the current config"""
    uri = generate_uri("/config")
    response = safe_request(
        "POST",
        uri,
        generate_headers(access_token),
        CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT,
        json={
            "subscription_domain": subscription_domain,
            "is_static_uri": is_static_uri,
            "is_device_cert": is_device_cert,
            "pen": pen,
        },
    )
    return response is None or is_success_response(response)


def update_username(
    access_token: str,
    user_name: str,
) -> bool:
    uri = generate_uri("/user")
    response = safe_request(
        "PATCH",
        uri,
        generate_headers(access_token),
        CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT,
        json={"user_name": user_name},
    )
    return response is None or is_success_response(response)


def download_certificate_authority_cert(access_token: str) -> bytes | None:
    """Downloads the current CA cert - returns the raw x509 bytes"""
    uri = generate_uri("/certificate/authority")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return response.content


def refresh_aggregator_cert(access_token: str) -> str | None:
    """Refreshes the current aggregator cert - returns the new password for the cert"""
    uri = generate_uri("/certificate/aggregator")
    response = safe_request("PUT", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return response.headers["X-Certificate-Password"]


def download_aggregator_cert(access_token: str) -> bytes | None:
    """Downloads the current cert - returns the raw p12 bytes"""
    uri = generate_uri("/certificate/aggregator")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return response.content


def download_aggregator_pem_cert(access_token: str) -> bytes | None:
    """Downloads the aggregator cert - returns .crt as bytes"""
    uri = generate_uri("/certificate/pem/aggregator")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return response.content


def download_aggregator_pem_key(access_token: str) -> bytes | None:
    """Downloads the aggregator cert - returns .key as bytes"""
    uri = generate_uri("/certificate/pem/aggregator?key=true")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return response.content


def download_device_pem_cert(access_token: str) -> bytes | None:
    """Downloads the aggregator cert - returns .crt as bytes"""
    uri = generate_uri("/certificate/pem/device")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return response.content


def download_device_pem_key(access_token: str) -> bytes | None:
    """Downloads the aggregator cert - returns .key as bytes"""
    uri = generate_uri("/certificate/pem/device?key=true")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return response.content


def refresh_device_cert(access_token: str) -> str | None:
    """Refreshes the current device cert - returns the new password for the cert"""
    uri = generate_uri("/certificate/device")
    response = safe_request("PUT", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return response.headers["X-Certificate-Password"]


def download_device_cert(access_token: str) -> bytes | None:
    """Downloads the device cert - returns the raw p12 bytes"""
    uri = generate_uri("/certificate/device")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return response.content


class InitialiseRunFailureType(IntEnum):
    NO_FAILURE = auto()
    UNKNOWN_FAILURE = auto()  # Failed for some sort of undetermined reason
    EXPIRED_CERT = auto()  # User certs have expired
    EXISTING_STATIC_INSTANCE = (
        auto()
    )  # User is expecting a static URI but one is already allocated (shut it down first)


@dataclass
class InitialiseRunResult:
    run_id: int | None  # The run_id that was initialised (or None for failure)
    failure_type: InitialiseRunFailureType


def init_run(access_token: str, run_group_id: int, test_procedure_id: str) -> InitialiseRunResult:
    """Creates a new test run underneath run_group_id, initialised with the specified test_procedure_id"""
    uri = generate_uri(f"/run_group/{run_group_id}/run")
    response = safe_request(
        "POST",
        uri,
        generate_headers(access_token),
        CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_SPAWN,
        json={"test_procedure_id": test_procedure_id},
    )

    # Figure out what sort of failure has occurred (if any)
    failure_type = InitialiseRunFailureType.NO_FAILURE
    run_id: int | None = None
    if response is None or not is_success_response(response):
        failure_type = InitialiseRunFailureType.UNKNOWN_FAILURE
        if response is not None:
            if response.status_code == HTTPStatus.EXPECTATION_FAILED:
                failure_type = InitialiseRunFailureType.EXPIRED_CERT
            elif response.status_code == HTTPStatus.CONFLICT:
                failure_type = InitialiseRunFailureType.EXISTING_STATIC_INSTANCE
    else:
        run_id = int(response.json()["run_id"])

    return InitialiseRunResult(run_id=run_id, failure_type=failure_type)


def start_run(access_token: str, run_id: str) -> StartResult:
    """Given an already initialised run - move it to the "started" state"""
    uri = generate_uri(f"/run/{run_id}")
    response = safe_request("POST", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)

    if response is None:
        return StartResult(success=False, error_message="Internal server error. Try again later.")

    if is_success_response(response):
        return StartResult(success=True, error_message=None)
    elif response.status_code == HTTPStatus.PRECONDITION_FAILED:
        try:
            error_data = response.json()
            return StartResult(success=False, error_message=error_data["detail"])
        except Exception as exc:
            logger.error("Unable to parse error response", exc_info=exc)
            return StartResult(
                success=False, error_message="Unexpected response. One or more preconditions are not met."
            )
    else:
        return StartResult(success=False, error_message="Unexpected error when attempting to start the run.")


def finalise_run(access_token: str, run_id: str) -> bytes | None:
    """Given an already started run - finalise it and return the resulting ZIP file bytes"""
    uri = generate_uri(f"/run/{run_id}/finalise")
    response = safe_request("POST", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    # This is a special case - we DID finalize but got no data due to a downstream error. Treat it as a general failure.
    if response.status_code == HTTPStatus.NO_CONTENT:
        return None

    return response.content


def fetch_run_artifact(access_token: str, run_id: str) -> bytes | None:
    """Given an already started run - finalise it and return the resulting ZIP file bytes"""
    uri = generate_uri(f"/run/{run_id}/artifact")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return response.content


def fetch_runs_for_group(
    access_token: str, run_group_id: int, page: int, finalised: bool | None
) -> Pagination[RunResponse] | None:
    """Fetches runs for a page"""
    uri = generate_uri(f"/run_group/{run_group_id}/run?page={page}")
    if finalised is not None:
        uri = uri + f"&finalised={finalised}"

    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return handle_pagination(
        response.json(),
        lambda r: RunResponse(
            run_id=r["run_id"],
            test_procedure_id=r["test_procedure_id"],
            test_url=r["test_url"],
            status=r["status"],
            all_criteria_met=r["all_criteria_met"],
            created_at=r["created_at"],
            finalised_at=r["finalised_at"],
            is_device_cert=r["is_device_cert"],
        ),
    )


def fetch_individual_run(access_token: str, run_id: str) -> RunResponse | None:
    """Fetches runs for a page"""
    uri = generate_uri(f"/run/{run_id}")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    r = response.json()
    return RunResponse(
        run_id=r["run_id"],
        test_procedure_id=r["test_procedure_id"],
        test_url=r["test_url"],
        status=r["status"],
        all_criteria_met=r["all_criteria_met"],
        created_at=r["created_at"],
        finalised_at=r["finalised_at"],
        is_device_cert=r["is_device_cert"],
    )


def delete_individual_run(access_token: str, run_id: str) -> bool:
    """Deletes a single run (cleaning up any existing resources)"""
    uri = generate_uri(f"/run/{run_id}")
    response = safe_request("DELETE", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return False

    return True


def fetch_run_status(access_token: str, run_id: str) -> str | None:
    """Given an already started run - fetch the status as a raw JSON string"""
    uri = generate_uri(f"/run/{run_id}/status")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return response.text


def fetch_procedure_yaml(access_token: str, test_procedure_id: str) -> str | None:
    """Given a test procedure ID - fetch the test procedure ID as a raw yaml string"""

    uri = generate_uri(f"/procedure/{test_procedure_id}")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return response.text


def fetch_group_runs_for_procedure(
    access_token: str, run_group_id: int, test_procedure_id: str
) -> Pagination[RunResponse] | None:
    """Given a test procedure ID - fetch the runs  (under a run group)"""

    uri = generate_uri(f"procedure_runs/{run_group_id}/{test_procedure_id}")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return handle_pagination(
        response.json(),
        lambda r: RunResponse(
            run_id=r["run_id"],
            test_procedure_id=r["test_procedure_id"],
            test_url=r["test_url"],
            status=r["status"],
            all_criteria_met=r["all_criteria_met"],
            created_at=r["created_at"],
            finalised_at=r["finalised_at"],
            is_device_cert=r["is_device_cert"],
        ),
    )


def fetch_group_procedure_run_summaries(
    access_token: str, run_group_id: int
) -> list[ProcedureRunSummaryResponse] | None:
    """Fetch all test procedures and their associated run summaries (under a run group)"""

    uri = generate_uri(f"procedure_runs/{run_group_id}")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return [
        ProcedureRunSummaryResponse(
            test_procedure_id=r["test_procedure_id"],
            description=r["description"],
            category=r["category"],
            classes=r["classes"] if "classes" in r else None,
            run_count=r["run_count"],
            latest_all_criteria_met=r["latest_all_criteria_met"],
        )
        for r in response.json()
    ]


def fetch_csip_aus_versions(access_token: str, page: int) -> Pagination[CSIPAusVersionResponse] | None:
    """Fetches available csip-aus versions for a page"""
    uri = generate_uri(f"/version?page={page}")

    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return handle_pagination(
        response.json(),
        lambda v: CSIPAusVersionResponse(
            version=v["version"],
        ),
    )


def fetch_run_groups(access_token: str, page: int) -> Pagination[RunGroupResponse] | None:
    """Fetches available run groups for the current user"""
    uri = generate_uri(f"/run_group?page={page}")

    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return handle_pagination(
        response.json(),
        lambda r: RunGroupResponse(
            created_at=r["created_at"],
            csip_aus_version=r["csip_aus_version"],
            name=r["name"],
            run_group_id=r["run_group_id"],
            total_runs=r["total_runs"],
        ),
    )


def create_run_group(access_token: str, csip_aus_version: str) -> RunGroupResponse | None:
    """Creates a new run group with the specified csip aus version - returns the created"""
    uri = generate_uri("/run_group")
    response = safe_request(
        "POST",
        uri,
        generate_headers(access_token),
        CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT,
        json={"csip_aus_version": csip_aus_version},
    )
    if response is None or not is_success_response(response):
        return None

    raw_response = response.json()
    return RunGroupResponse(
        created_at=raw_response["created_at"],
        csip_aus_version=raw_response["csip_aus_version"],
        name=raw_response["name"],
        run_group_id=raw_response["run_group_id"],
        total_runs=raw_response["total_runs"],
    )


def update_run_group(access_token: str, run_group_id: int, name: str) -> RunGroupResponse | None:
    """updates an existing run group with the specified id - returns the updated version of the RunGroup"""
    uri = generate_uri(f"/run_group/{run_group_id}")
    response = safe_request(
        "PUT",
        uri,
        generate_headers(access_token),
        CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT,
        json={"name": name},
    )
    if response is None or not is_success_response(response):
        return None

    raw_response = response.json()
    return RunGroupResponse(
        created_at=raw_response["created_at"],
        csip_aus_version=raw_response["csip_aus_version"],
        name=raw_response["name"],
        run_group_id=raw_response["run_group_id"],
        total_runs=raw_response["total_runs"],
    )


def delete_run_group(access_token: str, run_group_id: int) -> bool:
    """updates an existing run group with the specified id - returns the updated version of the RunGroup"""
    uri = generate_uri(f"/run_group/{run_group_id}")
    response = safe_request(
        "DELETE",
        uri,
        generate_headers(access_token),
        CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT,
    )
    if response is None or not is_success_response(response):
        return False

    return True


# ----------------------------------------------------------------------------------
#
#  Admin only functions
#
# ----------------------------------------------------------------------------------


def admin_fetch_users(access_token: str, page: int) -> Pagination[UserResponse] | None:
    """Fetch the list of all users (admin only)"""
    uri = generate_uri(f"/admin/users?page={page}")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return handle_pagination(
        response.json(),
        lambda i: UserResponse(
            user_id=i["user_id"],
            name=i["name"],
            run_groups=i["run_groups"],
        ),
    )


def admin_fetch_run_groups(access_token: str, run_group_id: int, page: int) -> Pagination[RunGroupResponse] | None:
    """Fetches available run groups for the user with run_group_id (admin only)

    Since this is for the admin user we can't identify the user using the access token.
    """
    uri = generate_uri(f"/admin/run_group?run_group_id={run_group_id}&page={page}")

    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return handle_pagination(
        response.json(),
        lambda r: RunGroupResponse(
            created_at=r["created_at"],
            csip_aus_version=r["csip_aus_version"],
            name=r["name"],
            run_group_id=r["run_group_id"],
            total_runs=r["total_runs"],
        ),
    )


def admin_fetch_group_procedure_run_summaries(
    access_token: str, run_group_id: int
) -> list[ProcedureRunSummaryResponse] | None:
    """Fetch all test procedures and their associated run summaries (under a run group)"""

    uri = generate_uri(f"/admin/procedure_runs/{run_group_id}")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return [
        ProcedureRunSummaryResponse(
            test_procedure_id=r["test_procedure_id"],
            description=r["description"],
            category=r["category"],
            classes=r["classes"] if "classes" in r else None,
            run_count=r["run_count"],
            latest_all_criteria_met=r["latest_all_criteria_met"],
        )
        for r in response.json()
    ]


def admin_fetch_run_artifact(access_token: str, run_id: str) -> bytes | None:
    """Given an already started run - finalise it and return the resulting ZIP file bytes"""
    uri = generate_uri(f"/admin/run/{run_id}/artifact")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return response.content


def admin_fetch_group_runs_for_procedure(
    access_token: str, run_group_id: int, test_procedure_id: str
) -> Pagination[RunResponse] | None:
    """Given a test procedure ID - fetch the runs  (under a run group)"""

    uri = generate_uri(f"/admin/procedure_runs/{run_group_id}/{test_procedure_id}")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return handle_pagination(
        response.json(),
        lambda r: RunResponse(
            run_id=r["run_id"],
            test_procedure_id=r["test_procedure_id"],
            test_url=r["test_url"],
            status=r["status"],
            all_criteria_met=r["all_criteria_met"],
            created_at=r["created_at"],
            finalised_at=r["finalised_at"],
            is_device_cert=r["is_device_cert"],
        ),
    )


def admin_fetch_runs_for_group(
    access_token: str, run_group_id: int, page: int, finalised: bool | None
) -> Pagination[RunResponse] | None:
    """Fetches runs for a page"""
    uri = generate_uri(f"/admin/run_group/{run_group_id}/run?page={page}")
    if finalised is not None:
        uri = uri + f"&finalised={finalised}"

    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return handle_pagination(
        response.json(),
        lambda r: RunResponse(
            run_id=r["run_id"],
            test_procedure_id=r["test_procedure_id"],
            test_url=r["test_url"],
            status=r["status"],
            all_criteria_met=r["all_criteria_met"],
            created_at=r["created_at"],
            finalised_at=r["finalised_at"],
            is_device_cert=r["is_device_cert"],
        ),
    )


def admin_fetch_run_status(access_token: str, run_id: str) -> str | None:
    """Given an already started run - fetch the status as a raw JSON string"""
    uri = generate_uri(f"/admin/run/{run_id}/status")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return response.text


def admin_fetch_individual_run(access_token: str, run_id: str) -> RunResponse | None:
    """Fetches runs for a page"""
    uri = generate_uri(f"/admin/run/{run_id}")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    r = response.json()
    return RunResponse(
        run_id=r["run_id"],
        test_procedure_id=r["test_procedure_id"],
        test_url=r["test_url"],
        status=r["status"],
        all_criteria_met=r["all_criteria_met"],
        created_at=r["created_at"],
        finalised_at=r["finalised_at"],
        is_device_cert=r["is_device_cert"],
    )
