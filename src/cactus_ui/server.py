"""Python Flask WebApp Auth0 integration example"""

import io
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache, wraps
from os import environ as env
from pathlib import Path
from typing import Any, Callable, TypeVar, cast
from urllib.parse import quote_plus, urlencode

import requests
from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import (
    Flask,
    current_app,
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
CACTUS_ORCHESTRATOR_BASEURL = env["CACTUS_ORCHESTRATOR_BASEURL"]
CACTUS_ORCHESTRATOR_AUDIENCE = env["CACTUS_ORCHESTRATOR_AUDIENCE"]
CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT = int(env.get("CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT", "30"))
CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_SPAWN = int(env.get("CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_SPAWN", "300"))
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


@app.route("/domain", methods=["GET", "POST"])
@login_required
def domain_page(access_token: str) -> str:
    error = None
    domain = ""

    headers = {"Authorization": f"Bearer {access_token}"}
    domain_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/domain"

    if request.method == "POST":
        # Update domain => POST on upstream /domain
        if request.form.get("action") == "update":
            field_sub_domain = request.form.get("subscription_domain")
            domain_resp = requests.post(
                domain_url,
                headers=headers,
                timeout=CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT,
                json={"subscription_domain": field_sub_domain},
            )
            if domain_resp.status_code < 200 or domain_resp.status_code >= 300:
                error = "Failed to update domain. Please ensure it's a FQDN in the form 'my.example.domain.com'"
            else:
                domain = domain_resp.json().get("subscription_domain", None)
        else:
            error = f"Unexpected form action {request.form.get("action")}"
    else:
        # GET Method
        domain_resp = requests.get(domain_url, headers=headers, timeout=CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
        if domain_resp.status_code < 200 or domain_resp.status_code >= 300:
            error = "Failed to fetch domain."
        else:
            domain = domain_resp.json().get("subscription_domain", None)

    # If the request fails
    return render_template("domain.html", error=error, domain=domain)


@app.route("/certificate", methods=["GET", "POST"])
@login_required
def certificate_page(access_token: str) -> str | Response:
    cert_url = None
    error = None
    pwd = None

    if request.method == "POST":
        # Refresh cert => PUT on upstream /certificate
        if request.form.get("action") == "refresh":
            cert_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/certificate"
            headers = {"Authorization": f"Bearer {access_token}"}

            cert_resp = requests.put(cert_url, headers=headers, timeout=CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
            if cert_resp.status_code != 200:
                error = "Failed to generate certificate."
            else:
                pwd = cert_resp.headers["X-Certificate-Password"]

        # Download certificate => GET on upstream /certificate (returns .p12 file)
        elif request.form.get("action") == "download":
            cert_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/certificate"
            headers = {"Authorization": f"Bearer {access_token}"}

            cert_resp = requests.get(cert_url, headers=headers, timeout=CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)

            if cert_resp.status_code != 200:
                error = "Failed to retrieve the certificate."
            else:
                return Response(
                    cert_resp.content,
                    mimetype="application/x-pkcs12",
                    headers={"Content-Disposition": "attachment;filename=certificate.p12"},
                )

    return render_template("certificate.html", pwd=pwd, error=error)


@app.route("/config", methods=["GET", "POST"])
@login_required
def config_page(access_token: str) -> str | Response:
    cert_url = None
    error = None
    pwd = None
    domain = None
    static_uri_example = None
    config_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/config"
    headers = {"Authorization": f"Bearer {access_token}"}

    # Handling download options is treated as a special case (as we don't need to fetch the latest settings)
    if request.method == "POST" and request.form.get("action") == "download":
        cert_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/certificate"
        headers = {"Authorization": f"Bearer {access_token}"}

        cert_resp = requests.get(cert_url, headers=headers, timeout=CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)

        if cert_resp.status_code != 200:
            return render_template(
                "config.html",
                pwd=pwd,
                error="Failed to retrieve the certificate.",
                domain=domain,
                static_uri_example=static_uri_example,
            )
        else:
            return Response(
                cert_resp.content,
                mimetype="application/x-pkcs12",
                headers={"Content-Disposition": "attachment;filename=certificate.p12"},
            )

    if request.method == "POST":
        # Refresh cert => PUT on upstream /certificate
        if request.form.get("action") == "refresh":
            cert_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/certificate"
            headers = {"Authorization": f"Bearer {access_token}"}

            cert_resp = requests.put(cert_url, headers=headers, timeout=CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
            if cert_resp.status_code != 200:
                error = "Failed to generate certificate."
            else:
                pwd = cert_resp.headers["X-Certificate-Password"]

        # Download certificate => GET on upstream /certificate (returns .p12 file)
        elif request.form.get("action") == "download":
            cert_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/certificate"
            headers = {"Authorization": f"Bearer {access_token}"}

            cert_resp = requests.get(cert_url, headers=headers, timeout=CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)

            if cert_resp.status_code != 200:
                error = "Failed to retrieve the certificate."
            else:
                return Response(
                    cert_resp.content,
                    mimetype="application/x-pkcs12",
                    headers={"Content-Disposition": "attachment;filename=certificate.p12"},
                )
        else:
            # GET Method

            domain_resp = requests.get(config_url, headers=headers, timeout=CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
            if domain_resp.status_code < 200 or domain_resp.status_code >= 300:
                error = "Failed to fetch domain."
            else:
                domain = domain_resp.json().get("subscription_domain", None)

    return render_template("config.html", pwd=pwd, error=error, domain=domain, static_uri_example=static_uri_example)


@app.route("/runs", methods=["GET", "POST"])
@login_required
def runs_page(access_token: str) -> str | Response:  # noqa: C901

    # Handle POST for triggering a new run / precondition phase
    headers = {"Authorization": f"Bearer {access_token}"}
    if request.method == "POST":
        if request.form.get("action") == "initialise":
            test_procedure_id = request.form.get("test_procedure_id")
            if test_procedure_id:
                run_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/run"
                payload = {"test_procedure_id": test_procedure_id}

                response = requests.post(
                    run_url, json=payload, headers=headers, timeout=CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_SPAWN
                )

                if response.status_code == 201:
                    # Refresh the page after run creation
                    return redirect(url_for("runs_page"))
                elif response.status_code == 409:
                    error = "Your certificate has expired. Please generate and download a new certificate."
                else:
                    error = "Failed to trigger a new run."
                return render_template("runs.html", error=error)

        # Handle starting a run / test procedure phase
        if request.form.get("action") == "start":
            run_id = request.form.get("run_id")
            if run_id:
                start_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/run/{run_id}"
                headers = {"Authorization": f"Bearer {access_token}"}

                response = requests.post(
                    start_url, headers=headers, timeout=CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT
                )

                if response.status_code == 200:
                    return redirect(url_for("runs_page"))
                else:
                    error = "Failed to finalise the run or retrieve artifacts."

        # Handle finalising a run
        if request.form.get("action") == "finalise":
            run_id = request.form.get("run_id")
            if run_id:
                finalise_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/run/{run_id}/finalise"
                headers = {"Authorization": f"Bearer {access_token}"}

                response = requests.post(
                    finalise_url, headers=headers, timeout=CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT
                )

                if response.status_code == 200:
                    return send_file(
                        io.BytesIO(response.content),
                        as_attachment=True,
                        download_name=f"{run_id}_artifacts.zip",
                        mimetype="application/zip",
                    )
                else:
                    error = "Failed to finalise the run or retrieve artifacts."

        # Handle dl artifact
        elif request.form.get("action") == "artifact":
            run_id = request.form.get("run_id")
            if run_id:
                artifact_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/run/{run_id}/artifact"
                response = requests.get(
                    artifact_url, headers=headers, timeout=CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT
                )

                if response.status_code == 200:
                    # forward zip to user
                    return send_file(
                        io.BytesIO(response.content),
                        as_attachment=True,
                        download_name=f"{run_id}_artifacts.zip",
                        mimetype="application/zip",
                    )

                else:
                    error = "Failed to retrieve artifacts."

    # Fetch list of runs
    page = request.args.get("page", 1, type=int)
    runs_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/run?page={page}"
    headers = {"Authorization": f"Bearer {access_token}"}

    response = requests.get(runs_url, headers=headers, timeout=CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT_DEFAULT)
    if response.status_code == 200:
        runs_data = response.json()
        runs = runs_data.get("items", [])
        pagination = _handle_pagination(runs_data)

        # fetch procedures
        procedures = fetch_procedures(headers)

        return render_template(
            "runs.html",
            runs=runs,
            next_page=pagination.next_page,
            prev_page=pagination.prev_page,
            total_items=pagination.total_items,
            page_size=pagination.page_size,
            current_page=pagination.current_page,
            procedures=procedures,
        )
    # NOTE: Orchestrator API raises 4xx (? check this), for a new user that has never had a cert generated.
    elif response.status_code >= 400 and response.status_code < 500:
        error = "Please generate a certificate."
        return render_template("runs.html", error=error)

    else:
        error = "Failed to retrieve runs."
        return render_template("runs.html", error=error)


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
