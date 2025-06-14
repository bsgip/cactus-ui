"""Python Flask WebApp Auth0 integration example"""

import io
from dataclasses import dataclass
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
CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT = 300
CACTUS_PLATFORM_VERSION = env["CACTUS_PLATFORM_VERSION"]
CACTUS_PLATFORM_SUPPORT_EMAIL = env["CACTUS_PLATFORM_SUPPORT_EMAIL"]

F = TypeVar("F", bound=Callable[..., object])


def login_required(f: F) -> F:
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return cast(F, decorated)


@dataclass
class Pagination:
    total_pages: int
    total_items: int
    page_size: int
    current_page: int
    prev_page: int | None
    next_page: int | None


def _handle_pagination(paginated_json: dict) -> Pagination:
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
    )


def fetch_procedures(headers: dict) -> list:
    # Fetch the list of test procedures for the dropdown
    procedures_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/procedure"
    procedures_response = requests.get(procedures_url, headers=headers, timeout=CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT)
    procedures = []
    if procedures_response.status_code == 200:
        procedures = procedures_response.json().get("items", [])
    return procedures


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
def procedures_page() -> str:
    page = request.args.get("page", 1, type=int)  # Default to page 1
    procedures_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/procedure?page={page}"
    headers = {"Authorization": f"Bearer {session['user']['access_token']}"}

    # Request the paginated list of procedures from upstream
    response = requests.get(procedures_url, headers=headers, timeout=CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT)

    # If the request is successful
    if response.status_code == 200:
        procedures_data = response.json()
        procedures = procedures_data.get("items", [])
        pagination = _handle_pagination(procedures_data)

        return render_template(
            "procedures.html",
            procedures=procedures,
            next_page=pagination.next_page,
            prev_page=pagination.prev_page,
            total_items=pagination.total_items,
            page_size=pagination.page_size,
            current_page=pagination.current_page,
        )

    # If the request fails
    error = "Failed to retrieve procedures."
    return render_template("procedures.html", error=error)


@app.route("/domain", methods=["GET", "POST"])
@login_required
def domain_page() -> str:
    error = None
    domain = ""

    headers = {"Authorization": f"Bearer {session['user']['access_token']}"}
    domain_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/domain"

    if request.method == "POST":
        # Update domain => POST on upstream /domain
        if request.form.get("action") == "update":
            field_sub_domain = request.form.get("subscription_domain")
            domain_resp = requests.post(
                domain_url,
                headers=headers,
                timeout=CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT,
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
        domain_resp = requests.get(domain_url, headers=headers, timeout=CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT)
        if domain_resp.status_code < 200 or domain_resp.status_code >= 300:
            error = "Failed to fetch domain."
        else:
            domain = domain_resp.json().get("subscription_domain", None)

    # If the request fails
    return render_template("domain.html", error=error, domain=domain)


@app.route("/certificate", methods=["GET", "POST"])
@login_required
def certificate_page() -> str | Response:
    cert_url = None
    error = None
    pwd = None

    if request.method == "POST":
        # Refresh cert => PUT on upstream /certificate
        if request.form.get("action") == "refresh":
            cert_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/certificate"
            headers = {"Authorization": f"Bearer {session['user']['access_token']}"}

            cert_resp = requests.put(cert_url, headers=headers, timeout=CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT)
            if cert_resp.status_code != 200:
                error = "Failed to generate certificate."
            else:
                pwd = cert_resp.headers["X-Certificate-Password"]

        # Download certificate => GET on upstream /certificate (returns .p12 file)
        elif request.form.get("action") == "download":
            cert_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/certificate"
            headers = {"Authorization": f"Bearer {session['user']['access_token']}"}

            cert_resp = requests.get(cert_url, headers=headers, timeout=CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT)

            if cert_resp.status_code != 200:
                error = "Failed to retrieve the certificate."
            else:
                return Response(
                    cert_resp.content,
                    mimetype="application/x-pkcs12",
                    headers={"Content-Disposition": "attachment;filename=certificate.p12"},
                )

    return render_template("certificate.html", pwd=pwd, error=error)


@app.route("/runs", methods=["GET", "POST"])
@login_required
def runs_page() -> str | Response:  # noqa: C901

    # Handle POST for triggering a new run / precondition phase
    headers = {"Authorization": f"Bearer {session['user']['access_token']}"}
    if request.method == "POST":
        if request.form.get("action") == "initialise":
            test_procedure_id = request.form.get("test_procedure_id")
            if test_procedure_id:
                run_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/run"
                payload = {"test_procedure_id": test_procedure_id}

                response = requests.post(
                    run_url, json=payload, headers=headers, timeout=CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT
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
                headers = {"Authorization": f"Bearer {session['user']['access_token']}"}

                response = requests.post(start_url, headers=headers, timeout=CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT)

                if response.status_code == 200:
                    return redirect(url_for("runs_page"))
                else:
                    error = "Failed to finalise the run or retrieve artifacts."

        # Handle finalising a run
        if request.form.get("action") == "finalise":
            run_id = request.form.get("run_id")
            if run_id:
                finalise_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/run/{run_id}/finalise"
                headers = {"Authorization": f"Bearer {session['user']['access_token']}"}

                response = requests.post(finalise_url, headers=headers, timeout=CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT)

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
                response = requests.get(artifact_url, headers=headers, timeout=CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT)

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
    headers = {"Authorization": f"Bearer {session['user']['access_token']}"}

    response = requests.get(runs_url, headers=headers, timeout=CACTUS_ORCHESTRATOR_REQUEST_TIMEOUT)
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
def logout() -> Response:
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
