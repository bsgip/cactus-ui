import logging
import re
from dataclasses import dataclass
from enum import IntEnum, auto
from http import HTTPStatus
from os import environ as env
from typing import Any, Callable

import cactus_schema.orchestrator as orchestrator
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
class StartResult:
    success: bool
    error_message: str | None


def handle_pagination(
    paginated_json: dict, item_parser: Callable[[dict], orchestrator.PaginatedType]
) -> orchestrator.Pagination[orchestrator.PaginatedType]:
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

    return orchestrator.Pagination(
        total_pages=total_pages,
        total_items=paginated_json.get("total", 0),
        page_size=paginated_json.get("size", 10),
        current_page=current_page,
        prev_page=prev_page,
        next_page=next_page,
        items=[item_parser(i) for i in paginated_json.get("items", [])],
    )


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


@dataclass
class PlaylistRunInfo:
    run_id: int
    test_procedure_id: str


@dataclass
class InitialisePlaylistResult:
    first_run_id: int | None  # The first run_id in the playlist (or None for failure)
    playlist_execution_id: str | None
    playlist_runs: list[PlaylistRunInfo] | None
    failure_type: InitialiseRunFailureType


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


def file_name_safe(v: str) -> str:
    return re.sub(r"[^A-Za-z0-9_\-]", "_", v)


def generate_run_artifact_file_name(response: requests.Response, run_id: str) -> str:
    raw_run_id = response.headers.get(orchestrator.HEADER_RUN_ID, run_id)
    user = response.headers.get(orchestrator.HEADER_USER_NAME, "")
    test_id = response.headers.get(orchestrator.HEADER_TEST_ID, "")
    group_name = response.headers.get(orchestrator.HEADER_GROUP_NAME, "")
    return file_name_safe(f"{raw_run_id}_{test_id}_{user}_{group_name}_artifacts") + ".zip"


def fetch_procedures(
    access_token: str, page: int
) -> orchestrator.Pagination[orchestrator.TestProcedureResponse] | None:
    """Fetch the list of test procedures for the dropdown"""
    uri = generate_uri(orchestrator.uri.ProcedureList + f"?page={page}")
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return handle_pagination(response.json(), lambda i: orchestrator.TestProcedureResponse.from_dict(i))


def fetch_config(access_token: str) -> orchestrator.UserConfigurationResponse | None:
    """Fetch the current config"""
    uri = generate_uri(orchestrator.uri.Config)
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    parsed_body = orchestrator.UserConfigurationResponse.from_json(response.text)
    if isinstance(parsed_body, list):
        return parsed_body[0]
    else:
        return parsed_body


def update_config(
    access_token: str,
    subscription_domain: str | None = None,
    is_static_uri: bool | None = None,
    pen: int | None = None,
) -> bool:
    """Update the current config"""
    uri = generate_uri(orchestrator.uri.Config)

    response = safe_request(
        "POST",
        uri,
        generate_headers(access_token),
        CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT,
        json=orchestrator.UserConfigurationRequest(
            subscription_domain=subscription_domain, is_static_uri=is_static_uri, pen=pen
        ).to_dict(),
    )
    return response is None or is_success_response(response)


def update_username(
    access_token: str,
    user_name: str,
) -> bool:
    uri = generate_uri(orchestrator.uri.User)
    response = safe_request(
        "PATCH",
        uri,
        generate_headers(access_token),
        CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT,
        json={"user_name": user_name},
    )
    return response is None or is_success_response(response)


def download_certificate_authority_cert(access_token: str) -> bytes | None:
    """Downloads the current CA cert - returns the raw x509 PEM bytes"""
    uri = generate_uri(orchestrator.uri.CertificateAuthority)
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return response.content


def try_read_file_name(response: requests.Response, default_val: str) -> str:
    content_disposition = response.headers.get("Content-Disposition", None)
    if content_disposition and "filename=" in content_disposition:
        return content_disposition.split("filename=")[1]
    else:
        return default_val


def download_client_cert(access_token: str, run_group_id: int) -> tuple[bytes | None, str | None]:
    """Downloads the current client certificate for run_group_id - returns the raw x509 PEM bytes AND an
    appropriate file name"""

    uri = generate_uri(orchestrator.uri.CertificateRunGroup.format(run_group_id=run_group_id))
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return (None, None)

    return (response.content, try_read_file_name(response, "client.pem"))


def generate_client_cert(access_token: str, run_group_id: int, is_device_cert: bool) -> tuple[bytes | None, str | None]:
    """Generates a new client certificate for run_group_id - returns a ZIP stream with all the data and an appropriate
    file name"""

    uri = generate_uri(orchestrator.uri.CertificateRunGroup.format(run_group_id=run_group_id))
    response = safe_request(
        "PUT",
        uri,
        generate_headers(access_token),
        CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT,
        json={"is_device_cert": is_device_cert},
    )
    if response is None or not is_success_response(response):
        return (None, None)

    return (response.content, try_read_file_name(response, "client.pem"))


def init_run(access_token: str, run_group_id: int, test_procedure_id: str) -> InitialiseRunResult:
    """Creates a new test run underneath run_group_id, initialised with the specified test_procedure_id"""
    uri = generate_uri(orchestrator.uri.RunGroupRunList.format(run_group_id=run_group_id))
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


def init_playlist(
    access_token: str, run_group_id: int, test_procedure_ids: list[str], start_index: int = 0
) -> InitialisePlaylistResult:
    """Creates a playlist of test runs underneath run_group_id, optionally starting from a specific index"""
    uri = generate_uri(orchestrator.uri.RunGroupRunList.format(run_group_id=run_group_id))
    request_body: dict = {"test_procedure_ids": test_procedure_ids}
    if start_index > 0:
        request_body["start_index"] = start_index
    response = safe_request(
        "POST",
        uri,
        generate_headers(access_token),
        CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_SPAWN,
        json=request_body,
    )

    failure_type = InitialiseRunFailureType.NO_FAILURE
    first_run_id: int | None = None
    playlist_execution_id: str | None = None
    playlist_runs: list[PlaylistRunInfo] | None = None

    if response is None or not is_success_response(response):
        failure_type = InitialiseRunFailureType.UNKNOWN_FAILURE
        if response is not None:
            if response.status_code == HTTPStatus.EXPECTATION_FAILED:
                failure_type = InitialiseRunFailureType.EXPIRED_CERT
            elif response.status_code == HTTPStatus.CONFLICT:
                failure_type = InitialiseRunFailureType.EXISTING_STATIC_INSTANCE
    else:
        data = response.json()
        first_run_id = int(data["run_id"])
        playlist_execution_id = data.get("playlist_execution_id")
        if data.get("playlist_runs"):
            playlist_runs = [
                PlaylistRunInfo(run_id=r["run_id"], test_procedure_id=r["test_procedure_id"])
                for r in data["playlist_runs"]
            ]

    return InitialisePlaylistResult(
        first_run_id=first_run_id,
        playlist_execution_id=playlist_execution_id,
        playlist_runs=playlist_runs,
        failure_type=failure_type,
    )


def start_run(access_token: str, run_id: str) -> StartResult:
    """Given an already initialised run - move it to the "started" state"""
    uri = generate_uri(orchestrator.uri.Run.format(run_id=run_id))
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
    uri = generate_uri(orchestrator.uri.RunFinalise.format(run_id=run_id))
    response = safe_request("POST", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    # This is a special case - we DID finalize but got no data due to a downstream error. Treat it as a general failure.
    if response.status_code == HTTPStatus.NO_CONTENT:
        return None

    return response.content


def fetch_run_artifact(access_token: str, run_id: str) -> tuple[bytes | None, str]:
    """Given an already started run - finalise it and return the resulting ZIP file bytes / file name"""
    uri = generate_uri(orchestrator.uri.RunArtifact.format(run_id=run_id))
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return (None, "")

    return (response.content, generate_run_artifact_file_name(response, run_id))


def fetch_runs_for_group(
    access_token: str, run_group_id: int, page: int, finalised: bool | None
) -> orchestrator.Pagination[orchestrator.RunResponse] | None:
    """Fetches runs for a page"""
    uri = generate_uri(orchestrator.uri.RunGroupRunList.format(run_group_id=run_group_id) + f"?page={page}")
    if finalised is not None:
        uri = uri + f"&finalised={finalised}"

    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return handle_pagination(response.json(), lambda r: orchestrator.RunResponse.from_dict(r))


def fetch_individual_run(access_token: str, run_id: str) -> orchestrator.RunResponse | None:
    """Fetches runs for a page"""
    uri = generate_uri(orchestrator.uri.Run.format(run_id=run_id))
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    parsed_body = orchestrator.RunResponse.from_json(response.text)
    if isinstance(parsed_body, list):
        return parsed_body[0]
    else:
        return parsed_body


def delete_individual_run(access_token: str, run_id: str) -> bool:
    """Deletes a single run (cleaning up any existing resources)"""
    uri = generate_uri(orchestrator.uri.Run.format(run_id=run_id))
    response = safe_request("DELETE", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return False

    return True


def fetch_run_status(access_token: str, run_id: str) -> str | None:
    """Given an already started run - fetch the status as a raw JSON string"""
    uri = generate_uri(orchestrator.uri.RunStatus.format(run_id=run_id))
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return response.text


def fetch_procedure_yaml(access_token: str, test_procedure_id: str) -> str | None:
    """Given a test procedure ID - fetch the test procedure ID as a raw yaml string"""

    uri = generate_uri(orchestrator.uri.Procedure.format(test_procedure_id=test_procedure_id))
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return response.text


def fetch_group_runs_for_procedure(
    access_token: str, run_group_id: int, test_procedure_id: str
) -> orchestrator.Pagination[orchestrator.RunResponse] | None:
    """Given a test procedure ID - fetch the runs  (under a run group)"""

    uri = generate_uri(
        orchestrator.uri.ProcedureRunGroupRunsList.format(
            run_group_id=run_group_id, test_procedure_id=test_procedure_id
        )
    )
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return handle_pagination(response.json(), lambda r: orchestrator.RunResponse.from_dict(r))


def fetch_group_procedure_run_summaries(
    access_token: str, run_group_id: int
) -> list[orchestrator.TestProcedureRunSummaryResponse] | None:
    """Fetch all test procedures and their associated run summaries (under a run group)"""

    uri = generate_uri(orchestrator.uri.ProcedureRunGroupList.format(run_group_id=run_group_id))
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    parsed_body = orchestrator.TestProcedureRunSummaryResponse.from_json(response.text)
    if not isinstance(parsed_body, list):
        return [parsed_body]
    else:
        return parsed_body


def fetch_csip_aus_versions(
    access_token: str, page: int
) -> orchestrator.Pagination[orchestrator.CSIPAusVersionResponse] | None:
    """Fetches available csip-aus versions for a page"""
    uri = generate_uri(orchestrator.uri.VersionList + f"?page={page}")

    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return handle_pagination(
        response.json(),
        lambda v: orchestrator.CSIPAusVersionResponse(
            version=v["version"],
        ),
    )


def fetch_run_groups(access_token: str, page: int) -> orchestrator.Pagination[orchestrator.RunGroupResponse] | None:
    """Fetches available run groups for the current user"""
    uri = generate_uri(orchestrator.uri.RunGroupList + f"?page={page}")

    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return handle_pagination(response.json(), lambda r: orchestrator.RunGroupResponse.from_dict(r))


def fetch_request_details(access_token: str, request_id: int, run_id: str) -> str | None:
    """Fetch raw request/response data for a specific request."""
    uri = generate_uri(orchestrator.uri.RunRequest.format(run_id=run_id, request_id=request_id))

    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)

    if response is None or not is_success_response(response):
        return None

    return response.text


def create_run_group(access_token: str, csip_aus_version: str) -> orchestrator.RunGroupResponse | None:
    """Creates a new run group with the specified csip aus version - returns the created"""
    uri = generate_uri(orchestrator.uri.RunGroupList)
    response = safe_request(
        "POST",
        uri,
        generate_headers(access_token),
        CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT,
        json=orchestrator.RunGroupRequest(csip_aus_version=csip_aus_version).to_dict(),
    )
    if response is None or not is_success_response(response):
        return None

    body_data = orchestrator.RunGroupResponse.from_json(response.text)
    if isinstance(body_data, list):
        return body_data[0]
    else:
        return body_data


def update_run_group(access_token: str, run_group_id: int, name: str) -> orchestrator.RunGroupResponse | None:
    """updates an existing run group with the specified id - returns the updated version of the RunGroup"""
    uri = generate_uri(orchestrator.uri.RunGroup.format(run_group_id=run_group_id))
    response = safe_request(
        "PUT",
        uri,
        generate_headers(access_token),
        CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT,
        json=orchestrator.RunGroupUpdateRequest(name=name).to_dict(),
    )
    if response is None or not is_success_response(response):
        return None

    body_data = orchestrator.RunGroupResponse.from_json(response.text)
    if isinstance(body_data, list):
        return body_data[0]
    else:
        return body_data


def delete_run_group(access_token: str, run_group_id: int) -> bool:
    """updates an existing run group with the specified id - returns the updated version of the RunGroup"""
    uri = generate_uri(orchestrator.uri.RunGroup.format(run_group_id=run_group_id))
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


def get_matchable_description(u: dict) -> str:
    """Convert a user into a string that can be matched against a search term

    | characters are used to separate fields to prevent matching across fields.
    """
    matchable_description = f"{u["user_id"]}"
    if u["name"]:
        matchable_description += f"|{u["name"]}"
    for rg in u["run_groups"]:
        matchable_description += f"|{rg["run_group_id"]}|{rg["name"]}"
    return matchable_description


def admin_fetch_users(access_token: str) -> list[orchestrator.UserWithRunGroupsResponse] | None:
    """Fetch the list of all users (admin only)"""
    uri = generate_uri(orchestrator.uri.AdminUsersList)

    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    parsed_body = orchestrator.UserWithRunGroupsResponse.from_json(response.text)
    if not isinstance(parsed_body, list):
        return [parsed_body]
    else:
        return parsed_body


def admin_fetch_run_groups(
    access_token: str, run_group_id: int, page: int
) -> orchestrator.Pagination[orchestrator.RunGroupResponse] | None:
    """Fetches available run groups for the user with run_group_id (admin only)

    Since this is for the admin user we can't identify the user using the access token.
    """
    uri = generate_uri(orchestrator.uri.AdminRunGroupList + f"?run_group_id={run_group_id}&page={page}")

    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return handle_pagination(response.json(), lambda r: orchestrator.RunGroupResponse.from_dict(r))


def admin_fetch_group_procedure_run_summaries(
    access_token: str, run_group_id: int
) -> list[orchestrator.TestProcedureRunSummaryResponse] | None:
    """Fetch all test procedures and their associated run summaries (under a run group)"""

    uri = generate_uri(orchestrator.uri.AdminRunGroupProceduresList.format(run_group_id=run_group_id))
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    parsed_body = orchestrator.TestProcedureRunSummaryResponse.from_json(response.text)
    if not isinstance(parsed_body, list):
        return [parsed_body]
    else:
        return parsed_body


def admin_fetch_run_artifact(access_token: str, run_id: str) -> tuple[bytes | None, str]:
    """Given an already started run - finalise it and return the resulting ZIP file bytes and ZIP file name"""
    uri = generate_uri(orchestrator.uri.AdminRunArtifact.format(run_id=run_id))
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return (None, "")

    return (response.content, generate_run_artifact_file_name(response, run_id))


def admin_fetch_run_group_artifact(access_token: str, run_group_id: int) -> bytes | None:
    """Generates a compliance report for the specified run_group_id. Returns the resulting ZIP file bytes"""
    uri = generate_uri(orchestrator.uri.AdminRunGroupCompliance.format(run_group_id=run_group_id))
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return response.content


def admin_fetch_group_runs_for_procedure(
    access_token: str, run_group_id: int, test_procedure_id: str
) -> orchestrator.Pagination[orchestrator.RunResponse] | None:
    """Given a test procedure ID - fetch the runs  (under a run group)"""

    uri = generate_uri(
        orchestrator.uri.AdminRunGroupProcedureRunList.format(
            run_group_id=run_group_id, test_procedure_id=test_procedure_id
        )
    )
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return handle_pagination(response.json(), lambda r: orchestrator.RunResponse.from_dict(r))


def admin_fetch_runs_for_group(
    access_token: str, run_group_id: int, page: int, finalised: bool | None
) -> orchestrator.Pagination[orchestrator.RunResponse] | None:
    """Fetches runs for a page"""
    uri = generate_uri(orchestrator.uri.AdminRunGroupRunList.format(run_group_id=run_group_id) + f"?page={page}")
    if finalised is not None:
        uri = uri + f"&finalised={finalised}"

    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return handle_pagination(response.json(), lambda r: orchestrator.RunResponse.from_dict(r))


def admin_fetch_run_status(access_token: str, run_id: str) -> str | None:
    """Given an already started run - fetch the status as a raw JSON string"""
    uri = generate_uri(orchestrator.uri.AdminRunStatus.format(run_id=run_id))
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    return response.text


def admin_fetch_individual_run(access_token: str, run_id: str) -> orchestrator.RunResponse | None:
    """Fetches runs for a page"""
    uri = generate_uri(orchestrator.uri.AdminRun.format(run_id=run_id))
    response = safe_request("GET", uri, generate_headers(access_token), CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response is None or not is_success_response(response):
        return None

    parsed_body = orchestrator.RunResponse.from_json(response.text)
    if isinstance(parsed_body, list):
        return parsed_body[0]
    else:
        return parsed_body
