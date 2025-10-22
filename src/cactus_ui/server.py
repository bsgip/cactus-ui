"""Python Flask WebApp Auth0 integration example"""

import io
import json
import logging
import logging.config
import os
from base64 import b64encode
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache, wraps
from http import HTTPStatus
from os import environ as env
from pathlib import Path
from typing import Any, Callable, TypeVar, cast
from urllib.parse import quote_plus, urlencode
import zipfile

from authlib.integrations.flask_client import OAuth
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
import jwt

import cactus_ui.orchestrator as orchestrator
from cactus_ui.common import find_first
from cactus_ui.compliance_class import fetch_compliance_classes

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

F = TypeVar("F", bound=Callable[..., object])


@dataclass
class GroupedProcedure:
    slug: str
    category: str
    summaries: list[orchestrator.ProcedureRunSummaryResponse]


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
    page = request.args.get("page", 1, type=int)  # Default to page 1

    user_pages = orchestrator.admin_fetch_users(access_token, page)
    if user_pages is None:
        # return render_template("admin.html", error="Failed to retrieve users.")
        users = [
            orchestrator.UserResponse(user_id=1, name="User 1", run_groups=[78]),
            orchestrator.UserResponse(user_id=2, name="User 2", run_groups=[12, 45]),
        ]
        return render_template("admin.html", users=users)

    return render_template(
        "admin.html",
        users=user_pages.items,
        next_page=user_pages.next_page,
        prev_page=user_pages.prev_page,
        total_items=user_pages.total_items,
        page_size=user_pages.page_size,
        current_page=user_pages.current_page,
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
                artifact_data = orchestrator.admin_fetch_run_artifact(access_token, run_id)
                if artifact_data is None:
                    error = "Failed to retrieve artifacts."
                else:
                    return send_file(
                        io.BytesIO(artifact_data),
                        as_attachment=True,
                        download_name=f"{run_id}_artifacts.zip",
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
    active_run_group: orchestrator.RunGroupResponse | None = None
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


@app.route("/procedures", methods=["GET"])
@login_required
def procedures_page(access_token: str) -> str:
    page = request.args.get("page", 1, type=int)  # Default to page 1

    # Request the paginated list of procedures from upstream
    procedure_pages = orchestrator.fetch_procedures(access_token, page)
    if procedure_pages is None:
        return render_template("procedures.html", error="Failed to retrieve procedures.")

    return render_template(
        "procedures.html",
        procedures=procedure_pages.items,
        next_page=procedure_pages.next_page,
        prev_page=procedure_pages.prev_page,
        total_items=procedure_pages.total_items,
        page_size=procedure_pages.page_size,
        current_page=procedure_pages.current_page,
    )


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
    pwd = None
    if request.method == "POST":
        action = request.form.get("action")
        certificate = request.form.get("certificate", None)
        if action == "refresh":
            if certificate == "aggregator":
                pwd = orchestrator.refresh_aggregator_cert(access_token)
            elif certificate == "device":
                pwd = orchestrator.refresh_device_cert(access_token)

            if pwd is None:
                error = f"Failed to generate/refresh {certificate} certificate."
        elif action == "download-certs":
            files = {}
            basename = f"{certificate}-cert"
            filename = f"{basename}-certificates.zip"
            if certificate == "aggregator":
                p12_cert_data = orchestrator.download_aggregator_cert(access_token)
                pem_cert = orchestrator.download_aggregator_pem_cert(access_token)
                pem_key = orchestrator.download_aggregator_pem_key(access_token)
                files = {f"{basename}.p12": p12_cert_data, f"{basename}.crt": pem_cert, f"{basename}.key": pem_key}
            elif certificate == "device":
                p12_cert_data = orchestrator.download_device_cert(access_token)
                pem_cert = orchestrator.download_device_pem_cert(access_token)
                pem_key = orchestrator.download_device_pem_key(access_token)
                files = {f"{basename}.p12": p12_cert_data, f"{basename}.crt": pem_cert, f"{basename}.key": pem_key}
            if not files:
                error = f"Failed to retrieve certificates for {certificate}."
            else:
                return send_zip_file(filename=filename, files=files)

        elif action == "download-ca":
            cert_data = mimetype = filename = None
            if certificate == "authority":
                cert_data = orchestrator.download_certificate_authority_cert(access_token)
                mimetype = "application/x-x509-ca-cert"
                filename = "cactus-ca-certificate.der"
            if cert_data is None or mimetype is None or filename is None:
                error = f"Failed to retrieve {certificate} certificate."
            else:
                return send_file(
                    io.BytesIO(cert_data),
                    as_attachment=True,
                    download_name=filename,
                    mimetype=mimetype,
                )
        elif action == "setcert":
            is_device_cert = certificate == "device"
            if not orchestrator.update_config(access_token, is_device_cert=is_device_cert):
                error = "Failed to swap device/aggregator certificate"
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
        pwd=pwd,
        error=error,
        domain=config.subscription_domain,
        static_uri=config.is_static_uri,
        static_uri_example=config.static_uri,
        is_device_cert=config.is_device_cert,
        aggregator_certificate_expiry=config.aggregator_certificate_expiry,
        device_certificate_expiry=config.device_certificate_expiry,
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
                if init_result.run_id is not None:
                    return redirect(url_for("run_status_page", run_id=init_result.run_id))
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
                artifact_data = orchestrator.fetch_run_artifact(access_token, run_id)
                if artifact_data is None:
                    error = "Failed to retrieve artifacts."
                else:
                    return send_file(
                        io.BytesIO(artifact_data),
                        as_attachment=True,
                        download_name=f"{run_id}_artifacts.zip",
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
    active_run_group: orchestrator.RunGroupResponse | None = None
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


@app.route("/run/<int:run_id>", methods=["GET", "POST"])
@login_required
def run_status_page(access_token: str, run_id: str) -> str | Response:
    error: str | None = None

    if request.method == "POST":
        if request.form.get("action") == "start":
            start_result = orchestrator.start_run(access_token, run_id)
            if not start_result or not start_result.success:
                error = (
                    "Failed to start the test run."
                    if start_result is None or start_result.error_message is None
                    else start_result.error_message
                )

        # Handle finalising a run
        elif request.form.get("action") == "finalise":
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

        # Handle downloading a prior run's artifacts
        elif request.form.get("action") == "artifact":
            artifact_data = orchestrator.fetch_run_artifact(access_token, run_id)
            if artifact_data is None:
                error = "Failed to retrieve artifacts."
            else:
                return send_file(
                    io.BytesIO(artifact_data),
                    as_attachment=True,
                    download_name=f"{run_id}_artifacts.zip",
                    mimetype="application/zip",
                )

    status = orchestrator.fetch_run_status(access_token=access_token, run_id=run_id)
    run_is_live = status is not None

    run_status = None
    run_test_uri = None
    run_procedure_id = None

    run_response = orchestrator.fetch_individual_run(access_token, run_id)
    if run_response:
        run_status = run_response.status
        run_test_uri = run_response.test_url
        run_procedure_id = run_response.test_procedure_id

    # Take the big JSON response string and encode it using base64 so we can embed it in the template and re-hydrate
    # it easily enough
    if status is not None:
        initial_status_b64 = b64encode(status.encode()).decode()
    else:
        initial_status_b64 = ""

    return render_template(
        "run_status.html",
        run_is_live=run_is_live,
        run_id=run_id,
        initial_status_b64=initial_status_b64,
        run_status=run_status,
        run_test_uri=run_test_uri,
        run_procedure_id=run_procedure_id,
        error=error,
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
    """

    return {
        "version": CACTUS_PLATFORM_VERSION,
        "hosted_images": get_hosted_images(),
        "support_email": CACTUS_PLATFORM_SUPPORT_EMAIL,
        "permissions": get_permissions(),
    }


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(env.get("PORT", 3000)), debug=True)  # nosec - not for deployment
