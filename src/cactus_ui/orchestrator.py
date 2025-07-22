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
class ProcedureResponse:
    """Ideally this would be defined in a shared cactus-schema but that doesn't exist. Instead, ensure this remains
    in sync with cactus-orchestrator.schema.Procedure"""

    test_procedure_id: str
    description: str
    category: str


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


@dataclass
class ProcedureRunSummaryResponse:
    """Ideally this would be defined in a shared cactus-schema but that doesn't exist. Instead, ensure this remains
    in sync with cactus-orchestrator.schema.TestProcedureRunSummaryResponse"""

    test_procedure_id: str
    description: str
    category: str
    run_count: int  # Count of runs for this test procedure
    latest_all_criteria_met: bool | None  # Value for all_criteria_met of the most recent Run


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
            test_procedure_id=i["test_procedure_id"], description=i["description"], category=i["category"]
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
    )


def update_config(
    access_token: str, subscription_domain: str | None, is_static_uri: bool | None, is_device_cert: bool | None
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
        },
    )
    return response is None or is_success_response(response)


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


def init_run(access_token: str, test_procedure_id: str) -> InitialiseRunResult:
    """Creates a new test run, initialiased with the specified test_procedure_id"""
    uri = generate_uri("/run")
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


def start_run(access_token: str, run_id: str) -> bool:
    """Given an already initialised run - move it to the "started" state"""
    uri = generate_uri(f"/run/{run_id}")
    response = safe_request("POST", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    return response is None or is_success_response(response)


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


def fetch_runs(access_token: str, page: int) -> Pagination[RunResponse] | None:
    """Fetches runs for a page"""
    uri = generate_uri(f"/run?page={page}")
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


def fetch_runs_for_procedure(access_token: str, test_procedure_id: str) -> Pagination[RunResponse] | None:
    """Given a test procedure ID - fetch the runs"""

    uri = generate_uri(f"procedure_runs/{test_procedure_id}")
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


def fetch_procedure_run_summaries(access_token: str) -> list[ProcedureRunSummaryResponse] | None:
    """Fetch all test procedures and their associated run summaries"""

    uri = generate_uri("procedure_runs")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return [
        ProcedureRunSummaryResponse(
            test_procedure_id=r["test_procedure_id"],
            description=r["description"],
            category=r["category"],
            run_count=r["run_count"],
            latest_all_criteria_met=r["latest_all_criteria_met"],
        )
        for r in response.json()
    ]
