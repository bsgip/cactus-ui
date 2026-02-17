"""Python Flask WebApp Auth0 integration example"""

import io
import json
import logging
import logging.config
import os
import zipfile
from base64 import b64encode
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache, wraps
from http import HTTPStatus
from os import environ as env
from pathlib import Path
from typing import Any, Callable, TypeVar, cast
from urllib.parse import quote_plus, urlencode
from cactus_schema.orchestrator.compliance import fetch_compliance_classes

import cactus_schema.orchestrator as schema
import jwt
from authlib.integrations.flask_client import OAuth
from dataclass_wizard import JSONWizard
from dotenv import find_dotenv, load_dotenv
from flask import (
    Flask,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.wrappers.response import Response

import cactus_ui.orchestrator as orchestrator
from cactus_ui.common import find_first
from cactus_ui.compliance_class import fetch_compliance_class

# Setup logs
logconf_fp = "./logconf.json"
if os.path.exists(logconf_fp):
    with open(logconf_fp, "r") as f:
        logging.config.dictConfig(json.load(f))
else:
    logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)


ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")
if not (env.get("CACTUS_UI_LOCALDEV", "false").lower() == "true"):
    app.wsgi_app = ProxyFix(app.wsgi_app)  # type: ignore


oauth = OAuth(app)  # type: ignore
oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "user:all openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)  # type: ignore

# envvars
CACTUS_ORCHESTRATOR_AUDIENCE = env["CACTUS_ORCHESTRATOR_AUDIENCE"]
CACTUS_PLATFORM_VERSION = env["CACTUS_PLATFORM_VERSION"]
CACTUS_PLATFORM_SUPPORT_EMAIL = env["CACTUS_PLATFORM_SUPPORT_EMAIL"]
BANNER_MESSAGE = env.get("BANNER_MESSAGE")
LOGIN_BANNER_MESSAGE = env.get("LOGIN_BANNER_MESSAGE")


@dataclass
class PlaylistConfig:
    id: str
    name: str
    procedures: list[str]
    description: str = ""


# Parse playlists from environment variable
CACTUS_PLAYLISTS: list[PlaylistConfig] = []
_playlists_raw = env.get("CACTUS_PLAYLISTS", "[]")
try:
    CACTUS_PLAYLISTS = [PlaylistConfig(**p) for p in json.loads(_playlists_raw)]
except (json.JSONDecodeError, TypeError) as e:
    logger.warning(f"Failed to parse CACTUS_PLAYLISTS: {e}")

F = TypeVar("F", bound=Callable[..., object])


@dataclass
class GroupedProcedure:
    slug: str
    category: str
    summaries: list[schema.TestProcedureRunSummaryResponse]


def get_access_token() -> str | None:
    """Overly simple method for fetching an access token from the user's session. All validation will be handled at the
    service receiving this access_token - all we are validating is that there is one and that it hasn't expired

    Returns access_token if its present AND not expired. None otherwise."""

    if "user" not in session:
        logger.info("user not found in session.")
        return None

    user = session["user"]
    if user is None or "access_token" not in user:
        logger.info("access_token not found in user.")
        return None

    access_token = user["access_token"]
    if not access_token:
        logger.info("access_token appears to be empty.")
        return None

    # access_token should come paired with expires_at (the returned metadata from OAuth2)
    if "expires_at" not in user:
        logger.error("No expires_at was returned with access_token.")
        return None

    try:
        exp_time = datetime.fromtimestamp(float(user["expires_at"]), tz=timezone.utc)
        if exp_time < datetime.now(tz=timezone.utc):
            logger.info(f"User access_token expired at {exp_time}.")
            return None
    except Exception as exc:
        logger.error("Exception attempting to decode user expires_at.", exc_info=exc)
        return None

    return access_token


def get_username_from_session() -> str | None:
    """
    Extracts the username from the OAuth2 session token.

    Returns:
        Username string if user is logged in, None otherwise.
        Tries common OAuth2 fields in order of preference
    """
    if "user" not in session:
        return None

    user_info = session["user"].get("userinfo", {})

    return user_info.get("name")


def login_required(f: F) -> F:
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        access_token = get_access_token()
        if access_token is None:
            return redirect(url_for("login"))

        return f(access_token=access_token, *args, **kwargs)

    return cast(F, decorated)


def get_permissions() -> list[str] | None:
    if "user" not in session:
        return None

    user = session["user"]

    if "access_token" not in user:
        return None

    encoded_jwt = user["access_token"]
    decoded_jwt = jwt.decode(encoded_jwt, options={"verify_signature": False})

    if "permissions" not in decoded_jwt:
        return None

    return decoded_jwt["permissions"]


def admin_role_required(f: F) -> F:
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        permissions = get_permissions()
        if not permissions or "admin:all" not in permissions:
            return redirect(url_for("login_or_home_page"))

        return f(*args, **kwargs)

    return cast(F, decorated)


def parse_bool(v: str | None) -> bool:
    if not v:
        return False

    if v[0] in ["F", "f", "0"]:
        return False

    return True


def download_playlist_artifacts(access_token: str, run_ids: list[int], download_name: str) -> Response | None:
    """Download artifacts for multiple runs as a single ZIP file.

    Returns a Flask send_file response if successful, None otherwise.
    """
    if not run_ids:
        return None

    artifact_data = orchestrator.fetch_multiple_run_artifacts(access_token, run_ids)
    if artifact_data is None:
        return None

    return send_file(
        io.BytesIO(artifact_data),
        as_attachment=True,
        download_name=download_name,
        mimetype="application/zip",
    )


def run_summary_to_compliance_status(test_procedure: schema.TestProcedureRunSummaryResponse) -> str:
    ACTIVE_RUN_STATUSES = [1, 2, 6]  # initialized, started, provisioning
    FINALIZED_RUN_STATUSES = [3, 4]  # finalized by user, finalized by timeout

    if test_procedure.latest_run_status in ACTIVE_RUN_STATUSES:
        return "active"
    elif test_procedure.run_count == 0:
        return "runless"
    elif test_procedure.latest_run_status in FINALIZED_RUN_STATUSES:
        if test_procedure.latest_all_criteria_met:
            return "success"
        else:
            return "failed"
    else:
        return "unknown"


def build_test_status_dict(run: schema.RunResponse) -> dict:
    """Build a test status dictionary from a RunResponse for playlist display."""
    return {
        "test_procedure_id": run.test_procedure_id,
        "run_id": run.run_id,
        "status": run.status.value if hasattr(run.status, "value") else str(run.status),
        "all_criteria_met": run.all_criteria_met,
        "has_artifacts": run.has_artifacts,
    }


# Controllers API
@app.route("/")
def login_or_home_page() -> str:
    if session.get("user") is None:
        return render_template(
            "login.html",
        )
    return render_template("home.html")


@app.route("/admin")
@login_required
@admin_role_required
def admin_page(access_token: str) -> str:
    users = orchestrator.admin_fetch_users(access_token)
    if users is None:
        return render_template("admin.html", error="Failed to retrieve users.")

    def custom_serializer(obj: Any) -> str | dict:
        if isinstance(obj, JSONWizard):
            # This is pretty crufty - but we're forcing in our own custom property
            # Josh - I wrote this on xmas eve (sue me) - probably better done with a subclass
            raw_data = obj.to_dict()
            raw_data["matchable_description"] = orchestrator.get_matchable_description(raw_data)
            return raw_data
        # other rely on standard serialization
        return json.dumps(obj)

    return render_template(
        "admin.html",
        users=users,
        users_b64=b64encode(json.dumps(users, default=custom_serializer).encode()).decode(),
    )


@app.route("/admin/group/<int:run_group_id>", methods=["GET", "POST"])
@login_required
@admin_role_required
def admin_run_group_page(access_token: str, run_group_id: int) -> str | Response:  # noqa: C901
    error: str | None = None
    """This is the admin-only page summarizing compliance across a run group"""

    if request.method == "POST":
        # Handle dl artifact
        if request.form.get("action") == "compliance":
            compliance_report = orchestrator.admin_fetch_run_group_artifact(access_token, run_group_id)
            if compliance_report is None:
                error = "There was an error generating the compliance report."
            else:
                return send_file(
                    io.BytesIO(compliance_report),
                    as_attachment=True,
                    download_name=f"{run_group_id}_compliance.pdf",
                    mimetype="application/pdf",
                )

    # Fetch procedures
    procedures = orchestrator.admin_fetch_group_procedure_run_summaries(
        access_token=access_token, run_group_id=run_group_id
    )

    compliance_by_class = {}

    if procedures is None:
        error = "Unabled to fetch test procedures."
    else:
        tests_by_class = defaultdict(list)
        for p in procedures:
            if p.classes:
                for c in p.classes:
                    tests_by_class[c].append(p.test_procedure_id)

        procedure_map = {p.test_procedure_id: p for p in procedures}

        for compliance_class, tests in tests_by_class.items():
            per_run_status = [
                {"procedure": procedure_map[t], "status": run_summary_to_compliance_status(procedure_map[t])}
                for t in tests
            ]
            compliant: bool = all([run["status"] == "success" for run in per_run_status])
            compliance_by_class[compliance_class] = {
                "class_details": fetch_compliance_class(compliance_class),
                "compliant": compliant,
                "per_run_status": per_run_status,
            }

    # Fetch the run groups (for the breadcrumbs selector)
    run_groups = orchestrator.admin_fetch_run_groups(access_token=access_token, run_group_id=run_group_id, page=1)
    active_run_group: schema.RunGroupResponse | None = None
    if not run_groups or not run_groups.items:
        error = "Unable to fetch run groups."
    else:
        for rg in run_groups.items:
            if rg.run_group_id == run_group_id:
                active_run_group = rg
                break

    return render_template(
        "run_group.html",
        error=error,
        compliance_by_class=compliance_by_class,
        run_groups=[] if run_groups is None else run_groups.items,
        run_group_id=run_group_id,
        active_run_group=active_run_group,
        is_admin_view=True,
    )


@app.route("/admin/group/<int:run_group_id>/runs", methods=["GET", "POST"])
@login_required
@admin_role_required
def admin_group_runs_page(access_token: str, run_group_id: int) -> str | Response:  # noqa: C901
    error: str | None = None
    """This is the admin equivalent of group_runs_page"""
    # Handle POST for triggering an artifact download
    if request.method == "POST":
        # Handle dl artifact
        if request.form.get("action") == "artifact":
            run_id = request.form.get("run_id")
            if not run_id:
                error = "No run ID specified."
            else:
                artifact_data, download_name = orchestrator.admin_fetch_run_artifact(access_token, run_id)
                if artifact_data is None:
                    error = "Failed to retrieve artifacts."
                else:
                    return send_file(
                        io.BytesIO(artifact_data),
                        as_attachment=True,
                        download_name=download_name,
                        mimetype="application/zip",
                    )

    # Fetch procedures
    procedures = orchestrator.admin_fetch_group_procedure_run_summaries(
        access_token=access_token, run_group_id=run_group_id
    )
    grouped_procedures: list[GroupedProcedure] = []

    all_classes: set[str] = set()
    classes_by_test: dict[str, list[str]] = {}
    tmp_classes_by_category: dict[str, set[str]] = {}

    if procedures is None:
        error = "Unable to fetch test procedures."
    else:
        # Organise the procedures by grouping them under the "category" label present (while also preserving order)
        for p in procedures:
            category_slug = p.category.replace(" ", "-")  # This could do with a more robust slugify method

            # Add this procedure to the list of groups
            existing_group = find_first(grouped_procedures, lambda x: x.slug == category_slug)
            if existing_group:
                existing_group.summaries.append(p)
            else:
                grouped_procedures.append(GroupedProcedure(category_slug, p.category, [p]))

            classes = p.classes if p.classes else []
            classes_by_test[p.test_procedure_id] = classes
            all_classes.update(classes)

            if category_slug in tmp_classes_by_category:
                tmp_classes_by_category[category_slug].update(classes)
            else:
                tmp_classes_by_category[category_slug] = set(classes)

    # convert sets to lists (sets are not serializable to json)
    classes_by_category: dict[str, list[str]] = {key: list(value) for key, value in tmp_classes_by_category.items()}

    # Fetch the run groups (for the breadcrumbs selector)
    run_groups = orchestrator.admin_fetch_run_groups(access_token=access_token, run_group_id=run_group_id, page=1)
    active_run_group: schema.RunGroupResponse | None = None
    if not run_groups or not run_groups.items:
        error = "Unable to fetch run groups."
    else:
        for rg in run_groups.items:
            if rg.run_group_id == run_group_id:
                active_run_group = rg
                break

    return render_template(
        "runs.html",
        error=error,
        grouped_procedures=grouped_procedures,
        classes=fetch_compliance_classes(all_classes),
        classes_by_test_b64=b64encode(json.dumps(classes_by_test).encode()).decode(),
        classes_by_category_b64=b64encode(json.dumps(classes_by_category).encode()).decode(),
        run_groups=[] if run_groups is None else run_groups.items,
        run_group_id=run_group_id,
        active_run_group=active_run_group,
        is_admin_view=True,
    )


@app.route("/admin/run_group/<int:run_group_id>/procedure_runs/<test_procedure_id>", methods=["GET"])
@login_required
@admin_role_required
def admin_procedure_runs_json(access_token: str, run_group_id: int, test_procedure_id: str) -> Response:
    runs_page = orchestrator.admin_fetch_group_runs_for_procedure(access_token, run_group_id, test_procedure_id)
    if runs_page is None:
        return Response(
            response=f"Unable to fetch runs for {test_procedure_id}.",
            status=HTTPStatus.NOT_FOUND,
            mimetype="text/plain",
        )

    return jsonify(runs_page)


@app.route("/admin/run_group/<int:run_group_id>/active_runs", methods=["GET"])
@login_required
@admin_role_required
def admin_active_runs_json(access_token: str, run_group_id: int) -> Response:
    runs_page = orchestrator.admin_fetch_runs_for_group(access_token, run_group_id, 1, False)
    if runs_page is None:
        return Response(
            response="Unable to load active runs.",
            status=HTTPStatus.NOT_FOUND,
            mimetype="text/plain",
        )

    return jsonify(runs_page)


@app.route("/admin/run/<int:run_id>", methods=["GET", "POST"])
@login_required
@admin_role_required
def admin_run_status_page(access_token: str, run_id: str) -> str | Response:
    error: str | None = None

    if request.method == "POST":
        # Handle downloading a prior run's artifacts
        if request.form.get("action") == "artifact":
            artifact_data, download_name = orchestrator.admin_fetch_run_artifact(access_token, run_id)
            if artifact_data is None:
                error = "Failed to retrieve artifacts."
            else:
                return send_file(
                    io.BytesIO(artifact_data),
                    as_attachment=True,
                    download_name=download_name,
                    mimetype="application/zip",
                )

    status = orchestrator.admin_fetch_run_status(access_token=access_token, run_id=run_id)
    run_is_live = status is not None

    run_status = None
    run_test_uri = None
    run_procedure_id = None
    run_has_artifacts = None

    run_response = orchestrator.admin_fetch_individual_run(access_token, run_id)
    if run_response:
        run_status = run_response.status
        run_test_uri = run_response.test_url
        run_procedure_id = run_response.test_procedure_id
        run_has_artifacts = run_response.has_artifacts

    # Take the big JSON response string and encode it using base64 so we can embed it in the template and re-hydrate
    # it easily enough
    if status is not None:
        initial_status_b64 = b64encode(status.encode()).decode()
    else:
        initial_status_b64 = ""

    return render_template(
        "run_status.html",
        run_is_live=run_is_live,
        run_has_artifacts=run_has_artifacts,
        run_id=run_id,
        initial_status_b64=initial_status_b64,
        run_status=run_status,
        run_test_uri=run_test_uri,
        run_procedure_id=run_procedure_id,
        error=error,
        playlist_info=None,
        is_admin_view=True,
        user_buttons_state="disabled",
        cactus_platform_support_email=CACTUS_PLATFORM_SUPPORT_EMAIL,
    )


@app.route("/admin/run/<int:run_id>/status", methods=["GET"])
@login_required
@admin_role_required
def admin_run_status_json(access_token: str, run_id: str) -> Response:

    status = orchestrator.admin_fetch_run_status(access_token=access_token, run_id=run_id)

    if status is None:
        return Response(
            response="Unable to fetch runner status. Likely terminated available.",
            status=HTTPStatus.GONE,
            mimetype="text/plain",
        )

    return Response(response=status, status=200, mimetype="application/json")


@app.route("/procedures", methods=["GET"])
@login_required
def procedures_page(access_token: str) -> str:
    """Get all test procedures, handling pagination."""
    all_procedures = []
    page = 1

    while True:
        procedure_pages = orchestrator.fetch_procedures(access_token, page)
        if procedure_pages is None:
            return render_template("procedures.html", error="Failed to retrieve procedures.")

        all_procedures.extend(procedure_pages.items)

        if procedure_pages.next_page is None:
            break

        page = procedure_pages.next_page

    return render_template("procedures.html", procedures=all_procedures)


@app.route("/procedure/<test_procedure_id>", methods=["GET"])
@login_required
def procedure_yaml_page(access_token: str, test_procedure_id: str) -> str | Response:

    error: str | None = None

    # Handle POST for triggering a new run / precondition phase
    # if request.method == "POST":
    #     if request.form.get("action") == "initialise":
    #         init_result = orchestrator.init_run(access_token, test_procedure_id)
    #         if init_result.run_id is not None:
    #             return redirect(url_for("run_status_page", run_id=init_result.run_id))
    #         elif init_result.failure_type == orchestrator.InitialiseRunFailureType.EXPIRED_CERT:
    #             error = "Your certificate has expired. Please generate and download a new certificate."
    #         elif init_result.failure_type == orchestrator.InitialiseRunFailureType.EXISTING_STATIC_INSTANCE:
    #             error = "You cannot start a second test run while your DeviceCapability URI is set to static."
    #         else:
    #             error = "Failed to trigger a new run due to an unknown error."

    # Request the paginated list of procedures from upstream
    yaml = orchestrator.fetch_procedure_yaml(access_token, test_procedure_id)
    if yaml is None:
        return render_template("procedure_yaml.html", error=f"Failed to fetch YAML for test '{test_procedure_id}'.")

    return render_template("procedure_yaml.html", test_procedure_id=test_procedure_id, yaml=yaml, error=error)


def send_zip_file(filename: str, files: dict[str, bytes | None]) -> Response:
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, mode="w") as zip_archive:
        for name, data in files.items():
            if data:
                zip_archive.writestr(zinfo_or_arcname=name, data=data)
    zip_buffer.seek(0)

    mimetype = "application/zip"
    return send_file(zip_buffer, as_attachment=True, download_name=filename, mimetype=mimetype)


@app.route("/config", methods=["GET", "POST"])
@login_required
def config_page(access_token: str) -> str | Response:  # noqa: C901
    error = None

    if request.method == "POST":
        action = request.form.get("action")
        if action == "downloadcert":
            run_group_id = int(request.form.get("run_group_id", ""))
            download_bytes, download_file_name = orchestrator.download_client_cert(access_token, run_group_id)
            if not download_bytes or not download_file_name:
                error = "Failed to retrieve certificate for run group."
            else:
                return send_file(
                    io.BytesIO(download_bytes), "application/x-x509-user-cert", True, download_name=download_file_name
                )

        elif action == "download-ca":
            download_bytes = orchestrator.download_certificate_authority_cert(access_token)
            mimetype = "application/x-x509-ca-cert"
            download_file_name = "cactus-serca.pem"
            if download_bytes is None:
                error = "Failed to retrieve SERCA."
            else:
                return send_file(
                    io.BytesIO(download_bytes),
                    as_attachment=True,
                    download_name=download_file_name,
                    mimetype=mimetype,
                )
        elif action == "generatesharedcertificateallrungroups":
            download_bytes, download_file_name = orchestrator.generate_shared_client_cert(access_token)
            if not download_bytes or not download_file_name:
                error = "Failed to generate a shared aggregator certificate for all run groups."
            else:
                return send_file(io.BytesIO(download_bytes), "application/zip", True, download_name=download_file_name)

        elif action == "generatedevice" or action == "generateagg":
            run_group_id = int(request.form.get("run_group_id", ""))
            download_bytes, download_file_name = orchestrator.generate_client_cert(
                access_token, run_group_id, action == "generatedevice"
            )
            if not download_bytes or not download_file_name:
                error = "Failed to generate certificate for run group."
            else:
                return send_file(io.BytesIO(download_bytes), "application/zip", True, download_name=download_file_name)

        elif action == "setpen":
            try:
                pen: int = int(request.form.get("pen", 0))
                if not orchestrator.update_config(access_token, pen=pen):
                    error = "Failed to update PEN"
            except ValueError:
                error = "Failed to parse PEN"
        elif action == "setsubscribeddomain":
            domain = request.form.get("subscription_domain", None)
            if domain is None:
                domain = ""
            if not orchestrator.update_config(access_token, subscription_domain=domain):
                error = "Failed to update subscription domain"
        elif action == "setstaticuri":
            static_uri = parse_bool(request.form.get("static_uri"))
            if not orchestrator.update_config(access_token, is_static_uri=static_uri):
                error = "Failed to update static URI"
        elif action == "updaterungroup":
            new_name = request.form["name"]
            run_group_id = int(request.form["run_group_id"])
            if not orchestrator.update_run_group(access_token, run_group_id, new_name):
                error = "Failed to update name"
        elif action == "createrungroup":
            version = request.form["version"]
            if not orchestrator.create_run_group(access_token, version):
                error = "Failed to create run group"
        elif action == "deleterungroup":
            run_group_id = int(request.form["run_group_id"])
            if not orchestrator.delete_run_group(access_token, run_group_id):
                error = "Failed to delete run group"

    # Fetch after doing any updates so we always render the latest version of the config
    config = orchestrator.fetch_config(access_token)
    run_groups = orchestrator.fetch_run_groups(access_token, 1)
    csip_aus_versions = orchestrator.fetch_csip_aus_versions(access_token, 1)
    if config is None or run_groups is None or csip_aus_versions is None:
        return render_template(
            "config.html",
            error="Unable to communicate with test server. Please try refreshing the page or re-logging in.",
        )

    return render_template(
        "config.html",
        error=error,
        domain=config.subscription_domain,
        static_uri=config.is_static_uri,
        static_uri_example=config.static_uri,
        run_groups=run_groups.items,
        csip_aus_versions=csip_aus_versions.items,
        pen=(
            "" if config.pen == 0 else config.pen
        ),  # A PEN of 0 is reserved. Replace with "" to trigger display of placeholder text # noqa: 501
    )


@app.route("/run_group/<int:run_group_id>/procedure_runs/<test_procedure_id>", methods=["GET"])
@login_required
def procedure_runs_json(access_token: str, run_group_id: int, test_procedure_id: str) -> Response:
    runs_page = orchestrator.fetch_group_runs_for_procedure(access_token, run_group_id, test_procedure_id)
    if runs_page is None:
        return Response(
            response=f"Unable to fetch runs for {test_procedure_id}.",
            status=HTTPStatus.NOT_FOUND,
            mimetype="text/plain",
        )

    return jsonify(runs_page)


@app.route("/run_group/<int:run_group_id>/active_runs", methods=["GET"])
@login_required
def active_runs_json(access_token: str, run_group_id: int) -> Response:
    runs_page = orchestrator.fetch_runs_for_group(access_token, run_group_id, 1, False)
    if runs_page is None:
        return Response(
            response="Unable to load active runs.",
            status=HTTPStatus.NOT_FOUND,
            mimetype="text/plain",
        )

    return jsonify(runs_page)


@app.route("/runs", methods=["GET"])
@login_required
def runs_page(access_token: str) -> str | Response:  # noqa: C901
    """Just redirects to the "first" RunGroup page"""

    run_groups = orchestrator.fetch_run_groups(access_token, 1)
    if not run_groups or not run_groups.items:
        return redirect(url_for("config_page"))

    return redirect(url_for("group_runs_page", run_group_id=run_groups.items[0].run_group_id))


@app.route("/group/<int:run_group_id>", methods=["GET"])
@login_required
def run_group_page(access_token: str, run_group_id: int) -> str:
    error: str | None = None
    """This page summarizes compliance across a run group"""

    # Fetch procedures
    procedures = orchestrator.fetch_group_procedure_run_summaries(access_token=access_token, run_group_id=run_group_id)

    compliance_by_class = {}

    if procedures is None:
        error = "Unabled to fetch test procedures."
    else:
        tests_by_class = defaultdict(list)
        for p in procedures:
            if p.classes:
                for c in p.classes:
                    tests_by_class[c].append(p.test_procedure_id)

        procedure_map = {p.test_procedure_id: p for p in procedures}

        for compliance_class, tests in tests_by_class.items():
            per_run_status = [
                {"procedure": procedure_map[t], "status": run_summary_to_compliance_status(procedure_map[t])}
                for t in tests
            ]
            compliant: bool = all([run["status"] == "success" for run in per_run_status])
            compliance_by_class[compliance_class] = {
                "class_details": fetch_compliance_class(compliance_class),
                "compliant": compliant,
                "per_run_status": per_run_status,
            }

    # Fetch the run groups (for the breadcrumbs selector)
    run_groups = orchestrator.fetch_run_groups(access_token=access_token, page=1)
    active_run_group: schema.RunGroupResponse | None = None
    if not run_groups or not run_groups.items:
        error = "Unable to fetch run groups."
    else:
        for rg in run_groups.items:
            if rg.run_group_id == run_group_id:
                active_run_group = rg
                break

    return render_template(
        "run_group.html",
        error=error,
        compliance_by_class=compliance_by_class,
        run_groups=[] if run_groups is None else run_groups.items,
        run_group_id=run_group_id,
        active_run_group=active_run_group,
        is_admin_view=False,
    )


@app.route("/group/<int:run_group_id>/runs", methods=["GET", "POST"])
@login_required
def group_runs_page(access_token: str, run_group_id: int) -> str | Response:  # noqa: C901
    error: str | None = None

    # Handle POST for triggering a new run / precondition phase
    if request.method == "POST":
        if request.form.get("action") == "initialise":
            test_procedure_id = request.form.get("test_procedure_id")
            if not test_procedure_id:
                error = "No test procedure selected."
            else:
                init_result = orchestrator.init_run(access_token, run_group_id, test_procedure_id)
                if init_result.response is not None:
                    return redirect(url_for("run_status_page", run_id=init_result.response.run_id))
                elif init_result.failure_type == orchestrator.InitialiseRunFailureType.EXPIRED_CERT:
                    error = "Your certificate has expired. Please generate and download a new certificate."
                elif init_result.failure_type == orchestrator.InitialiseRunFailureType.EXISTING_STATIC_INSTANCE:
                    error = "You cannot start a second test run while your DeviceCapability URI is set to static."
                else:
                    error = "Failed to trigger a new run due to an unknown error."

        # Handle starting a run / test procedure phase
        elif request.form.get("action") == "start":
            run_id = request.form.get("run_id")
            if not run_id:
                error = "No run ID specified."
            else:
                start_result = orchestrator.start_run(access_token, run_id)
                if start_result.success:
                    return redirect(url_for("run_status_page", run_id=run_id))
                else:
                    error = (
                        "Failed to start the test run."
                        if start_result.error_message is None
                        else start_result.error_message
                    )

        # Handle finalising a run
        elif request.form.get("action") == "finalise":
            run_id = request.form.get("run_id")
            if not run_id:
                error = "No run ID specified."
            else:
                archive_data = orchestrator.finalise_run(access_token, run_id)
                if archive_data is None:
                    error = "Failed to finalise the run or retrieve artifacts."
                else:
                    return send_file(
                        io.BytesIO(archive_data),
                        as_attachment=True,
                        download_name=f"{run_id}_artifacts.zip",
                        mimetype="application/zip",
                    )

        # Handle dl artifact
        elif request.form.get("action") == "artifact":
            run_id = request.form.get("run_id")
            if not run_id:
                error = "No run ID specified."
            else:
                artifact_data, download_name = orchestrator.fetch_run_artifact(access_token, run_id)
                if artifact_data is None:
                    error = "Failed to retrieve artifacts."
                else:
                    return send_file(
                        io.BytesIO(artifact_data),
                        as_attachment=True,
                        download_name=download_name,
                        mimetype="application/zip",
                    )
        # Handle deleting a prior run
        elif request.form.get("action") == "delete":
            run_id = request.form["run_id"]
            delete_result = orchestrator.delete_individual_run(access_token, run_id)
            if not delete_result:
                error = "Failed to delete run."

    # Fetch procedures
    procedures = orchestrator.fetch_group_procedure_run_summaries(access_token, run_group_id)
    grouped_procedures: list[GroupedProcedure] = []

    all_classes: set[str] = set()
    classes_by_test: dict[str, list[str]] = {}
    tmp_classes_by_category: dict[str, set[str]] = {}

    if procedures is None:
        error = "Unable to fetch test procedures."
    else:
        # Organise the procedures by grouping them under the "category" label present (while also preserving order)
        for p in procedures:
            category_slug = p.category.replace(" ", "-")  # This could do with a more robust slugify method

            # Add this procedure to the list of groups
            existing_group = find_first(grouped_procedures, lambda x: x.slug == category_slug)
            if existing_group:
                existing_group.summaries.append(p)
            else:
                grouped_procedures.append(GroupedProcedure(category_slug, p.category, [p]))

            classes = p.classes if p.classes else []
            classes_by_test[p.test_procedure_id] = classes
            all_classes.update(classes)

            if category_slug in tmp_classes_by_category:
                tmp_classes_by_category[category_slug].update(classes)
            else:
                tmp_classes_by_category[category_slug] = set(classes)

    # convert sets to lists (sets are not serializable to json)
    classes_by_category: dict[str, list[str]] = {key: list(value) for key, value in tmp_classes_by_category.items()}

    # Fetch the run groups (for the breadcrumbs selector)
    run_groups = orchestrator.fetch_run_groups(access_token, 1)
    active_run_group: schema.RunGroupResponse | None = None
    if not run_groups or not run_groups.items:
        error = "Unable to fetch run groups."
    else:
        for rg in run_groups.items:
            if rg.run_group_id == run_group_id:
                active_run_group = rg
                break

    return render_template(
        "runs.html",
        error=error,
        grouped_procedures=grouped_procedures,
        classes=fetch_compliance_classes(all_classes),
        classes_by_test_b64=b64encode(json.dumps(classes_by_test).encode()).decode(),
        classes_by_category_b64=b64encode(json.dumps(classes_by_category).encode()).decode(),
        run_groups=[] if run_groups is None else run_groups.items,
        run_group_id=run_group_id,
        active_run_group=active_run_group,
    )


@app.route("/playlists", methods=["GET"])
@login_required
def playlists_page(access_token: str) -> str | Response:
    """Redirects to the first RunGroup's playlists page"""
    run_groups = orchestrator.fetch_run_groups(access_token, 1)
    if not run_groups or not run_groups.items:
        return redirect(url_for("config_page"))

    return redirect(url_for("group_playlists_page", run_group_id=run_groups.items[0].run_group_id))


def _handle_initialise_playlist(access_token: str, run_group_id: int) -> str | Response | None:
    """Handle starting a playlist. Returns a redirect on success, an error string, or None."""
    playlist_id = request.form.get("playlist_id")
    start_index = int(request.form.get("start_index", "0"))
    if not playlist_id:
        return "No playlist selected."

    playlist = next((p for p in CACTUS_PLAYLISTS if p.id == playlist_id), None)
    if not playlist:
        return "Invalid playlist selected."

    init_result = orchestrator.init_playlist(access_token, run_group_id, playlist.procedures, start_index)
    if init_result.response is not None:
        if init_result.response.playlist_execution_id and init_result.response.playlist_runs:
            session["active_playlist"] = {
                "execution_id": init_result.response.playlist_execution_id,
                "name": playlist.name,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "runs": [
                    {"run_id": r.run_id, "test_procedure_id": r.test_procedure_id}
                    for r in init_result.response.playlist_runs
                ],
            }
        return redirect(url_for("run_status_page", run_id=init_result.response.run_id))
    elif init_result.failure_type == orchestrator.InitialiseRunFailureType.EXPIRED_CERT:
        return "Your certificate has expired. Please generate and download a new certificate."
    elif init_result.failure_type == orchestrator.InitialiseRunFailureType.EXISTING_STATIC_INSTANCE:
        return "You cannot start a second test run while your DeviceCapability URI is set to static."
    else:
        return "Failed to trigger playlist due to an unknown error."


def _handle_artifact_download(access_token: str) -> str | Response | None:
    """Handle downloading artifacts for a single run. Returns a file response, error string, or None."""
    run_id = request.form.get("run_id")
    if not run_id:
        return "No run ID specified."

    artifact_data, download_name = orchestrator.fetch_run_artifact(access_token, run_id)
    if artifact_data is None:
        return "Failed to retrieve artifacts."

    return send_file(
        io.BytesIO(artifact_data),
        as_attachment=True,
        download_name=download_name,
        mimetype="application/zip",
    )


def _handle_artifact_all_download(access_token: str) -> str | Response | None:
    """Handle downloading all artifacts for a playlist execution."""
    run_ids_raw = request.form.get("run_ids", "")
    playlist_name = request.form.get("playlist_name", "playlist")
    if not run_ids_raw:
        return "No run IDs specified."

    try:
        run_ids = [int(rid) for rid in run_ids_raw.split(",")]
    except ValueError:
        return "Invalid run IDs."

    first_run_id = run_ids[0]
    download_name = f"{playlist_name}_{first_run_id}_artifacts.zip"
    response = download_playlist_artifacts(access_token, run_ids, download_name)
    if response:
        return response
    return "Failed to retrieve artifacts."


def _handle_skip_playlist(access_token: str) -> str | Response | None:
    """Handle skipping remaining playlist tests and downloading artifacts."""
    run_id = request.form.get("run_id")
    if not run_id:
        return "No run ID specified."

    orchestrator.finalise_playlist(access_token, run_id)

    run_response = orchestrator.fetch_individual_run(access_token, run_id)
    if run_response and run_response.playlist_runs:
        run_ids = [r.run_id for r in run_response.playlist_runs]
        first_run_id = run_ids[0]
        download_name = f"playlist_{first_run_id}_artifacts.zip"
        response = download_playlist_artifacts(access_token, run_ids, download_name)
        if response:
            return response
    return "Failed to download playlist artifacts."


def _count_playlist_executions(access_token: str, run_group_id: int) -> dict[str, int]:
    """Count how many times each playlist has been executed in a run group."""
    playlist_run_counts: dict[str, int] = {p.id: 0 for p in CACTUS_PLAYLISTS}
    runs_page = orchestrator.fetch_runs_for_group(access_token, run_group_id, 1, None)
    if not runs_page:
        return playlist_run_counts

    playlist_executions: dict[str, list[schema.RunResponse]] = {}
    for run in runs_page.items:
        if run.playlist_execution_id:
            if run.playlist_execution_id not in playlist_executions:
                playlist_executions[run.playlist_execution_id] = []
            playlist_executions[run.playlist_execution_id].append(run)

    for exec_id, runs in playlist_executions.items():
        runs_sorted = sorted(runs, key=lambda r: r.playlist_order or 0)
        execution_procedures = [r.test_procedure_id for r in runs_sorted]
        for playlist in CACTUS_PLAYLISTS:
            if execution_procedures == playlist.procedures:
                playlist_run_counts[playlist.id] += 1
                break

    return playlist_run_counts


def _handle_playlists_post(access_token: str, run_group_id: int) -> str | Response | None:
    """Dispatch POST actions for the playlists page."""
    action = request.form.get("action")
    if action == "initialise_playlist":
        return _handle_initialise_playlist(access_token, run_group_id)
    elif action == "artifact":
        return _handle_artifact_download(access_token)
    elif action == "artifact_all":
        return _handle_artifact_all_download(access_token)
    elif action == "skip_playlist":
        return _handle_skip_playlist(access_token)
    return None


@app.route("/group/<int:run_group_id>/playlists", methods=["GET", "POST"])
@login_required
def group_playlists_page(access_token: str, run_group_id: int) -> str | Response:
    """Page for viewing and starting playlists"""
    error: str | None = None

    if request.method == "POST":
        result = _handle_playlists_post(access_token, run_group_id)
        if isinstance(result, Response):
            return result
        if isinstance(result, str):
            error = result

    # Fetch the run groups (for the breadcrumbs selector)
    run_groups = orchestrator.fetch_run_groups(access_token, 1)
    active_run_group: schema.RunGroupResponse | None = None
    if not run_groups or not run_groups.items:
        error = "Unable to fetch run groups."
    else:
        for rg in run_groups.items:
            if rg.run_group_id == run_group_id:
                active_run_group = rg
                break

    return render_template(
        "playlists.html",
        error=error,
        playlists=CACTUS_PLAYLISTS,
        playlist_run_counts=_count_playlist_executions(access_token, run_group_id),
        run_groups=[] if run_groups is None else run_groups.items,
        run_group_id=run_group_id,
        active_run_group=active_run_group,
    )


@app.route("/group/<int:run_group_id>/playlist_runs/<playlist_id>", methods=["GET"])
@login_required
def playlist_runs_json(access_token: str, run_group_id: int, playlist_id: str) -> Response:
    """Fetch run history for a specific playlist"""
    # Find the playlist config to get procedure IDs
    playlist = next((p for p in CACTUS_PLAYLISTS if p.id == playlist_id), None)
    if not playlist:
        return Response(
            response=json.dumps([]),
            status=HTTPStatus.OK,
            mimetype="application/json",
        )

    # Fetch all runs for this run group with playlist_execution_id set
    # Group them by playlist_execution_id
    runs_page = orchestrator.fetch_runs_for_group(access_token, run_group_id, 1, None)
    if runs_page is None:
        return Response(
            response=json.dumps([]),
            status=HTTPStatus.OK,
            mimetype="application/json",
        )

    # Group runs by playlist_execution_id
    playlist_executions: dict[str, list[schema.RunResponse]] = {}
    for run in runs_page.items:
        if run.playlist_execution_id:
            if run.playlist_execution_id not in playlist_executions:
                playlist_executions[run.playlist_execution_id] = []
            playlist_executions[run.playlist_execution_id].append(run)

    # Build response: list of playlist runs with test statuses
    result = []
    for exec_id, runs in playlist_executions.items():
        runs_sorted = sorted(runs, key=lambda r: r.playlist_order or 0)
        if not runs_sorted:
            continue

        # Check if this execution matches our playlist exactly
        # by comparing the procedure IDs in order
        execution_procedures = [r.test_procedure_id for r in runs_sorted]
        if execution_procedures != playlist.procedures:
            continue

        first_run = runs_sorted[0]

        # Build test status list
        test_statuses = [build_test_status_dict(run) for run in runs_sorted]

        # Check if any run has artifacts
        has_artifacts = any(r.has_artifacts for r in runs_sorted)

        result.append(
            {
                "playlist_execution_id": exec_id,
                "first_run_id": first_run.run_id,
                "created_at": first_run.created_at.isoformat(),
                "test_statuses": test_statuses,
                "has_artifacts": has_artifacts,
            }
        )

    # Sort by created_at descending (most recent first)
    result.sort(key=lambda x: str(x["created_at"]), reverse=True)

    return Response(
        response=json.dumps(result),
        status=HTTPStatus.OK,
        mimetype="application/json",
    )


@app.route("/group/<int:run_group_id>/active_playlists", methods=["GET"])
@login_required
def active_playlists_json(access_token: str, run_group_id: int) -> Response:
    """Fetch all active playlist executions (those with at least one non-finalized run)"""
    # Fetch all runs to find playlists with non-finalized runs (including initialised)
    all_runs_page = orchestrator.fetch_runs_for_group(access_token, run_group_id, 1, None)
    if all_runs_page is None:
        return Response(
            response=json.dumps([]),
            status=HTTPStatus.OK,
            mimetype="application/json",
        )

    # Statuses that indicate a playlist is still active (not completed)
    active_statuses = {"initialised", "started", "provisioning"}

    # Find playlist_execution_ids that have at least one active run
    active_playlist_ids: set[str] = set()
    for run in all_runs_page.items:
        status_str = run.status.value if hasattr(run.status, "value") else str(run.status)
        if run.playlist_execution_id and status_str in active_statuses:
            active_playlist_ids.add(run.playlist_execution_id)

    if not active_playlist_ids:
        return Response(
            response=json.dumps([]),
            status=HTTPStatus.OK,
            mimetype="application/json",
        )

    # Group all runs by playlist_execution_id, but only for active playlists
    playlist_executions: dict[str, list[schema.RunResponse]] = {}
    for run in all_runs_page.items:
        if run.playlist_execution_id and run.playlist_execution_id in active_playlist_ids:
            if run.playlist_execution_id not in playlist_executions:
                playlist_executions[run.playlist_execution_id] = []
            playlist_executions[run.playlist_execution_id].append(run)

    # Build response
    result = []
    for exec_id, runs in playlist_executions.items():
        runs_sorted = sorted(runs, key=lambda r: r.playlist_order or 0)
        if not runs_sorted:
            continue

        first_run = runs_sorted[0]

        # Find the playlist config to get the name
        playlist = next(
            (p for p in CACTUS_PLAYLISTS if first_run.test_procedure_id in p.procedures),
            None,
        )
        playlist_name = playlist.name if playlist else "Unknown Playlist"
        playlist_id = playlist.id if playlist else None

        # Build test status list
        test_statuses = [build_test_status_dict(run) for run in runs_sorted]

        result.append(
            {
                "playlist_execution_id": exec_id,
                "playlist_id": playlist_id,
                "playlist_name": playlist_name,
                "first_run_id": first_run.run_id,
                "created_at": first_run.created_at.isoformat(),
                "test_statuses": test_statuses,
            }
        )

    # Sort by created_at descending (most recent first)
    result.sort(key=lambda x: str(x["created_at"]), reverse=True)

    return Response(
        response=json.dumps(result),
        status=HTTPStatus.OK,
        mimetype="application/json",
    )


def _build_playlist_info(
    access_token: str, run_response: schema.RunResponse
) -> tuple[dict | None, int | None, dict | None]:
    """Build playlist template context from a run that belongs to a playlist.

    Returns (playlist_info, next_playlist_run_id, current_active_run).
    """
    if not run_response.playlist_runs:
        return None, None, None

    current_order = run_response.playlist_order
    active_playlist_session = session.get("active_playlist", {})

    playlist_runs_full: list[dict] = []
    first_run_started_at = None
    for i, r in enumerate(run_response.playlist_runs):
        full_run = orchestrator.fetch_individual_run(access_token, str(r.run_id))
        if full_run:
            if i == 0:
                first_run_started_at = full_run.created_at.isoformat() if full_run.created_at else None
            playlist_runs_full.append(build_test_status_dict(full_run))
        else:
            playlist_runs_full.append(
                {
                    "run_id": r.run_id,
                    "test_procedure_id": r.test_procedure_id,
                    "status": r.status.value if hasattr(r.status, "value") else str(r.status),
                    "all_criteria_met": None,
                    "has_artifacts": False,
                }
            )

    playlist_info = {
        "name": active_playlist_session.get("name", "Playlist"),
        "started_at": first_run_started_at,
        "runs": playlist_runs_full,
        "current_order": current_order,
        "total": len(run_response.playlist_runs),
    }

    next_playlist_run_id = None
    if current_order is not None and current_order + 1 < len(run_response.playlist_runs):
        next_playlist_run_id = run_response.playlist_runs[current_order + 1].run_id

    current_active_run = None
    for r in run_response.playlist_runs:
        if r.status in ["started", "provisioning"]:
            current_active_run = {
                "run_id": r.run_id,
                "test_procedure_id": r.test_procedure_id,
                "order": run_response.playlist_runs.index(r),
            }
            break

    return playlist_info, next_playlist_run_id, current_active_run


def _handle_run_status_post(access_token: str, run_id: str) -> str | Response | None:
    """Dispatch POST actions for the run status page."""
    action = request.form.get("action")
    if action == "start":
        start_result = orchestrator.start_run(access_token, run_id)
        if not start_result or not start_result.success:
            return (
                "Failed to start the test run."
                if start_result is None or start_result.error_message is None
                else start_result.error_message
            )
        return None
    elif action == "finalise":
        archive_data = orchestrator.finalise_run(access_token, run_id)
        if archive_data is None:
            return "Failed to finalise the run or retrieve artifacts."
        return send_file(
            io.BytesIO(archive_data),
            as_attachment=True,
            download_name=f"{run_id}_artifacts.zip",
            mimetype="application/zip",
        )
    elif action == "artifact":
        artifact_data, download_name = orchestrator.fetch_run_artifact(access_token, run_id)
        if artifact_data is None:
            return "Failed to retrieve artifacts."
        return send_file(
            io.BytesIO(artifact_data),
            as_attachment=True,
            download_name=download_name,
            mimetype="application/zip",
        )
    elif action == "skip_playlist":
        orchestrator.finalise_playlist(access_token, run_id)
        run_response = orchestrator.fetch_individual_run(access_token, run_id)
        if run_response and run_response.playlist_runs:
            run_ids = [r.run_id for r in run_response.playlist_runs]
            first_run_id = run_ids[0]
            playlist_name = session.get("active_playlist", {}).get("name", "playlist")
            download_name = f"{playlist_name}_{first_run_id}_artifacts.zip"
            response = download_playlist_artifacts(access_token, run_ids, download_name)
            if response:
                return response
        return "Failed to download playlist artifacts."
    return None


@app.route("/run/<int:run_id>", methods=["GET", "POST"])
@login_required
def run_status_page(access_token: str, run_id: str) -> str | Response:
    error: str | None = None

    if request.method == "POST":
        result = _handle_run_status_post(access_token, run_id)
        if isinstance(result, Response):
            return result
        if isinstance(result, str):
            error = result

    status = orchestrator.fetch_run_status(access_token=access_token, run_id=run_id)
    run_is_live = status is not None

    run_status = None
    run_test_uri = None
    run_procedure_id = None
    run_has_artifacts = None

    run_response = orchestrator.fetch_individual_run(access_token, run_id)
    if run_response:
        run_status = run_response.status
        run_test_uri = run_response.test_url
        run_procedure_id = run_response.test_procedure_id
        run_has_artifacts = run_response.has_artifacts

    initial_status_b64 = b64encode(status.encode()).decode() if status is not None else ""

    playlist_info, next_playlist_run_id, current_active_run = (
        _build_playlist_info(access_token, run_response) if run_response else (None, None, None)
    )

    return render_template(
        "run_status.html",
        run_is_live=run_is_live,
        run_has_artifacts=run_has_artifacts,
        run_id=run_id,
        initial_status_b64=initial_status_b64,
        run_status=run_status,
        run_test_uri=run_test_uri,
        run_procedure_id=run_procedure_id,
        error=error,
        playlist_info=playlist_info,
        next_playlist_run_id=next_playlist_run_id,
        current_active_run=current_active_run,
        cactus_platform_support_email=CACTUS_PLATFORM_SUPPORT_EMAIL,
    )


@app.route("/run/<int:run_id>/status", methods=["GET"])
@login_required
def run_status_json(access_token: str, run_id: str) -> Response:

    status = orchestrator.fetch_run_status(access_token=access_token, run_id=run_id)

    if status is None:
        return Response(
            response="Unable to fetch runner status. Likely terminated available.",
            status=HTTPStatus.GONE,
            mimetype="text/plain",
        )

    return Response(response=status, status=200, mimetype="application/json")


@app.route("/run/<int:run_id>/requests/<int:request_id>", methods=["GET"])
@login_required
def run_request_details(access_token: str, request_id: int, run_id: str) -> Response:
    """Fetch raw request/response data for a specific request."""

    request_data = orchestrator.fetch_request_details(access_token=access_token, request_id=request_id, run_id=run_id)

    if request_data is None:
        return Response(
            response=json.dumps({"error": "Request details not found"}),
            status=HTTPStatus.NOT_FOUND,
            mimetype="application/json",
        )

    return Response(response=request_data, status=HTTPStatus.OK, mimetype="application/json")


@app.route("/run/<int:run_id>/proceed", methods=["GET"])
@login_required
def send_proceed(access_token: str, run_id: str) -> Response:

    proceed_response = orchestrator.send_proceed(access_token=access_token, run_id=run_id)

    if proceed_response is None:
        return Response(response="Failed to proceed to next step", status=HTTPStatus.INTERNAL_SERVER_ERROR)

    return Response(response=proceed_response.to_json(), status=HTTPStatus.OK, mimetype="application/json")


@app.route("/callback", methods=["GET", "POST"])
def callback() -> Response:
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    access_token = get_access_token()

    # Try update the user's username on successful login
    if access_token and "userinfo" in token and "name" in token["userinfo"]:
        user_name = token["userinfo"]["name"]
        try:
            success = orchestrator.update_username(access_token=access_token, user_name=user_name)
            if not success:
                logger.error(f"Failed to update username '{user_name}'.")
        except Exception as e:
            logger.error(f"Exception trying to update username '{user_name}'", exc_info=e)
    else:
        logger.error("Unable to update username. User info or access token missing from token.")

    return redirect("/")


@app.route("/login")
def login() -> str:
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True), audience=CACTUS_ORCHESTRATOR_AUDIENCE
    )


@app.route("/logout")
@login_required
def logout(access_token: str) -> Response:
    session.clear()
    return redirect(
        "https://"
        + env["AUTH0_DOMAIN"]
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("login_or_home_page", _external=True),
                "client_id": env["AUTH0_CLIENT_ID"],
            },
            quote_via=quote_plus,
        )
    )


@lru_cache(maxsize=1)
def get_hosted_images() -> list[str]:
    root_path = Path(current_app.root_path)
    static_base_path = Path(current_app.static_folder) / "base"  # type: ignore
    return [str(f.relative_to(root_path)) for f in static_base_path.glob("*.webp")]


@app.context_processor
def inject_global_template_context() -> dict:
    """
    Injects global constants and assets used across all templates, specifically:
    - Injects images (.webp) into hosted by section of the base page's footer.
       o NOTE: All (.webp) images under './static/base/' path will be included.
    - sets platform version from CACTUS_PLATFORM_VERSION envvar
    - Adds support email from CACTUS_PLATFORM_SUPPORT_EMAIL envvar.
    - Adds the users name (if not None)
    - Adds the BANNER_MESSAGE and LOGIN_BANNER_MESSAGE envvars (both optional)
    """

    return {
        "version": CACTUS_PLATFORM_VERSION,
        "hosted_images": get_hosted_images(),
        "support_email": CACTUS_PLATFORM_SUPPORT_EMAIL,
        "permissions": get_permissions(),
        "username": get_username_from_session(),
        "banner_message": BANNER_MESSAGE,
        "login_banner_message": LOGIN_BANNER_MESSAGE,
    }


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(env.get("PORT", 3000)), debug=True)  # nosec - not for deployment
