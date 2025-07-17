"""Python Flask WebApp Auth0 integration example"""

import io
import logging
from base64 import b64encode
from datetime import datetime, timezone
from functools import lru_cache, wraps
from http import HTTPStatus
from os import environ as env
from pathlib import Path
from typing import Any, Callable, TypeVar, cast
from urllib.parse import quote_plus, urlencode

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

import cactus_ui.orchestrator as orchestrator
from cactus_ui.common import find_first

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
        "scope": "user:all",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)  # type: ignore

# envvars
CACTUS_ORCHESTRATOR_AUDIENCE = env["CACTUS_ORCHESTRATOR_AUDIENCE"]
CACTUS_PLATFORM_VERSION = env["CACTUS_PLATFORM_VERSION"]
CACTUS_PLATFORM_SUPPORT_EMAIL = env["CACTUS_PLATFORM_SUPPORT_EMAIL"]

F = TypeVar("F", bound=Callable[..., object])


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


@app.route("/procedure/<test_procedure_id>", methods=["GET", "POST"])
@login_required
def procedure_yaml_page(access_token: str, test_procedure_id: str) -> str | Response:

    error: str | None = None

    # Handle POST for triggering a new run / precondition phase
    if request.method == "POST":
        if request.form.get("action") == "initialise":
            init_result = orchestrator.init_run(access_token, test_procedure_id)
            if init_result.run_id is not None:
                return redirect(url_for("run_status_page", run_id=init_result.run_id))
            elif init_result.expired_cert:
                error = "Your certificate has expired. Please generate and download a new certificate."
            else:
                error = "Failed to trigger a new run."

    # Request the paginated list of procedures from upstream
    yaml = orchestrator.fetch_procedure_yaml(access_token, test_procedure_id)
    if yaml is None:
        return render_template("procedure_yaml.html", error=f"Failed to fetch YAML for test '{test_procedure_id}'.")

    return render_template("procedure_yaml.html", test_procedure_id=test_procedure_id, yaml=yaml, error=error)


@app.route("/config", methods=["GET", "POST"])
@login_required
def config_page(access_token: str) -> str | Response:

    # If we can't reach the current config - any page load will be borked. Best we can do is report on an error
    config = orchestrator.fetch_config(access_token)
    if config is None:
        return render_template(
            "config.html",
            error="Unable to communicate with test server. Please try refreshing the page or re-logging in.",
        )

    domain = config.subscription_domain
    static_uri_example = config.static_uri
    static_uri = config.is_static_uri
    error = None
    pwd = None

    if request.method == "POST":
        # Refresh cert - render the password
        if request.form.get("action") == "refresh":
            pwd = orchestrator.refresh_cert(access_token)
            if pwd is None:
                error = "Failed to generate certificate."

        # Download certificate - serve a new download
        elif request.form.get("action") == "download":
            cert_data = orchestrator.download_cert(access_token)
            if cert_data is None:
                error = "Failed to retrieve the certificate."
            else:
                return send_file(
                    io.BytesIO(cert_data),
                    as_attachment=True,
                    download_name="certificate.p12",
                    mimetype="application/x-pkcs12",
                )
        # Update the configuration
        elif request.form.get("action") == "update":
            domain = str(request.form.get("subscription_domain"))
            static_uri = parse_bool(request.form.get("static_uri"))

            if not orchestrator.update_config(
                access_token,
                subscription_domain=domain,
                is_static_uri=static_uri,
            ):
                error = "Failed to update configuration."
            else:
                # Need to refetch the new value for static_uri_example
                config = orchestrator.fetch_config(access_token)
                if config is None:
                    return render_template(
                        "config.html",
                        error="Unable to communicate with test server. Please try refreshing the page / re-logging in.",
                    )
                domain = config.subscription_domain
                static_uri = config.is_static_uri
                static_uri_example = config.static_uri

    return render_template(
        "config.html", pwd=pwd, error=error, domain=domain, static_uri=static_uri, static_uri_example=static_uri_example
    )


@app.route("/procedure_runs/<test_procedure_id>", methods=["GET"])
@login_required
def procedure_runs_json(access_token: str, test_procedure_id: str) -> Response:
    runs_page = orchestrator.fetch_runs_for_procedure(access_token, test_procedure_id)
    if runs_page is None:
        return Response(
            response=f"Unable to fetch runs for {test_procedure_id}.",
            status=HTTPStatus.NOT_FOUND,
            mimetype="text/plain",
        )

    return jsonify(runs_page)


@app.route("/runs", methods=["GET", "POST"])
@login_required
def runs_page(access_token: str) -> str | Response:  # noqa: C901
    error: str | None = None

    # Handle POST for triggering a new run / precondition phase
    if request.method == "POST":
        if request.form.get("action") == "initialise":
            test_procedure_id = request.form.get("test_procedure_id")
            if not test_procedure_id:
                error = "No test procedure selected."
            else:
                init_result = orchestrator.init_run(access_token, test_procedure_id)
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
                if orchestrator.start_run(access_token, run_id):
                    return redirect(url_for("run_status_page", run_id=run_id))
                else:
                    error = "Failed to start the test run."

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

    # Fetch procedures
    procedures = orchestrator.fetch_procedure_run_summaries(access_token)
    grouped_procedures: list[tuple[str, list[orchestrator.ProcedureRunSummaryResponse]]] = []
    if procedures is None:
        error = "Unable to fetch test procedures."
    else:
        # Organise the procedures by grouping them under the "category" label present (while also preserving order)
        for p in procedures:

            # Add this procedure to the list of groups
            existing_group = find_first(grouped_procedures, lambda x: x[0] == p.category)
            if existing_group:
                existing_group[1].append(p)
            else:
                grouped_procedures.append((p.category, [p]))

    return render_template(
        "runs.html",
        error=error,
        grouped_procedures=grouped_procedures,
    )


@app.route("/run/<run_id>", methods=["GET"])
@login_required
def run_status_page(access_token: str, run_id: str) -> str:

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
    )


@app.route("/run/<run_id>/status", methods=["GET"])
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
    }


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(env.get("PORT", 3000)), debug=True)  # nosec - not for deployment
