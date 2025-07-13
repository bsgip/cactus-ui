import logging
from dataclasses import dataclass
from enum import IntEnum, auto
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
CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_SPAWN = int(env.get("CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_SPAWN", "300"))


@dataclass
class RunResponse:
    """Ideally this would be defined in a shared cactus-schema but that doesn't exist. Instead, ensure this remains
    in sync with cactus-orchestrator.schema.RunResponse"""

    run_id: int
    test_procedure_id: str
    test_url: str
    status: str


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
    )


def update_config(access_token: str, subscription_domain: str, is_static_uri: bool) -> bool:
    """Update the current config"""
    uri = generate_uri("/config")
    response = safe_request(
        "POST",
        uri,
        generate_headers(access_token),
        CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT,
        json={"subscription_domain": subscription_domain, "is_static_uri": is_static_uri},
    )
    return response is None or is_success_response(response)


def refresh_cert(access_token: str) -> str | None:
    """Refreshes the current cert - returns the new password for the cert"""
    uri = generate_uri("/certificate")
    response = safe_request("PUT", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return response.headers["X-Certificate-Password"]


def download_cert(access_token: str) -> bytes | None:
    """Downloads the current cert - returns the raw p12 bytes"""
    uri = generate_uri("/certificate")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return response.content


@dataclass
class InitialiseRunResult:
    run_id: int | None  # The run_id that was initialised (or None for failure)
    expired_cert: bool  # True if the failure is due to an expired certificate


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

    expired_cert = False
    run_id: int | None = None
    if response is None or not is_success_response(response):
        if response is not None and response.status_code == 409:
            expired_cert = True
    else:
        run_id = int(response.json()["run_id"])

    return InitialiseRunResult(run_id=run_id, expired_cert=expired_cert)


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
            run_id=r["run_id"], test_procedure_id=r["test_procedure_id"], test_url=r["test_url"], status=r["status"]
        ),
    )


def fetch_run_status(access_token: str, run_id: str) -> dict[str, Any] | None:
    """Given an already started run - fetch the status as raw JSON"""
    uri = generate_uri(f"/run/{run_id}/status")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return response.json()
