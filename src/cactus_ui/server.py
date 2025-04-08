"""Python Flask WebApp Auth0 integration example"""

import io
from os import environ as env
from urllib.parse import quote_plus, urlencode
import requests

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, send_file, session, request, url_for
from werkzeug.wrappers.response import Response


ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")


oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "user:all",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)

CACTUS_ORCHESTRATOR_BASEURL = env["CACTUS_ORCHESTRATOR_BASEURL"]
CACTUS_ORCHESTRATOR_AUDIENCE = env["CACTUS_ORCHESTRATOR_AUDIENCE"]


# Controllers API
@app.route("/")
def home() -> str:
    return render_template(
        "home.html",
    )


@app.route("/procedures", methods=["GET"])
def procedures() -> str:
    page = request.args.get("page", 1, type=int)  # Default to page 1
    procedures_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/procedure?page={page}"
    headers = {"Authorization": f"Bearer {session['user']['access_token']}"}

    # Request the paginated list of procedures from upstream
    response = requests.get(procedures_url, headers=headers)

    # If the request is successful
    if response.status_code == 200:
        procedures_data = response.json()  # Assuming the API returns a paginated response in JSON
        procedures = procedures_data.get("items", [])  # List of procedures
        next_page = procedures_data.get("next", None)  # URL for the next page if available
        prev_page = procedures_data.get("previous", None)  # URL for the previous page if available
        total_items = procedures_data.get("total", 0)  # Total number of items in the collection
        page_size = procedures_data.get("page_size", 10)  # Number of items per page
        current_page = procedures_data.get("page", 1)  # Current page number

        return render_template(
            "procedures.html",
            procedures=procedures,
            next_page=next_page,
            prev_page=prev_page,
            total_items=total_items,
            page_size=page_size,
            current_page=current_page,
        )

    # If the request fails
    error = "Failed to retrieve procedures."
    return render_template("procedures.html", error=error)


@app.route("/certificate", methods=["GET", "POST"])
def certificate() -> str | Response:
    cert_url = None
    error = None
    pwd = None

    if request.method == "POST":
        # Refresh cert => PUT on upstream /certificate
        if request.form.get("action") == "refresh":
            cert_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/certificate"
            headers = {"Authorization": f"Bearer {session['user']['access_token']}"}

            cert_resp = requests.put(cert_url, headers=headers)
            pwd = cert_resp.headers["X-Certificate-Password"]
            if cert_resp.status_code != 200:
                error = "Failed to generate certificate."

        # Download certificate => GET on upstream /certificate (returns .p12 file)
        elif request.form.get("action") == "download":
            cert_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/certificate"
            headers = {"Authorization": f"Bearer {session['user']['access_token']}"}

            cert_resp = requests.get(cert_url, headers=headers)

            if cert_resp.status_code != 200:
                error = "Failed to retrieve the certificate."
            else:
                # The response should contain the certificate as a file
                # Return the certificate as a downloadable file to the user
                return Response(
                    cert_resp.content,
                    mimetype="application/x-pkcs12",
                    headers={"Content-Disposition": "attachment;filename=certificate.p12"},
                )

    return render_template("certificate.html", pwd=pwd, error=error)


@app.route("/runs", methods=["GET", "POST"])
def runs() -> str | Response:
    # Handle POST for triggering a new run
    if request.method == "POST":
        if request.form.get("action") == "trigger":
            test_procedure_id = request.form.get("test_procedure_id")
            if test_procedure_id:
                run_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/run"
                headers = {"Authorization": f"Bearer {session['user']['access_token']}"}
                payload = {"test_procedure_id": test_procedure_id}

                # Trigger the new run (POST request)
                response = requests.post(run_url, json=payload, headers=headers)

                if response.status_code == 201:
                    return redirect(url_for("runs"))  # Refresh the page after run creation
                else:
                    error = "Failed to trigger a new run."
                    return render_template("runs.html", error=error)

        # Handle finalising a run
        if request.form.get("action") == "finalise":
            run_id = request.form.get("run_id")
            if run_id:
                finalise_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/run/{run_id}/finalise"
                headers = {"Authorization": f"Bearer {session['user']['access_token']}"}

                response = requests.post(finalise_url, headers=headers)

                if response.status_code == 200:
                    # Handle the ZIP file (artifact download) if it's returned
                    zip_data = response.content  # This is the ZIP file returned by upstream

                    # You could also send the file as a download to the user:
                    return send_file(
                        io.BytesIO(zip_data),
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
                headers = {"Authorization": f"Bearer {session['user']['access_token']}"}

                response = requests.get(artifact_url, headers=headers)

                if response.status_code == 200:
                    # Handle the ZIP file (artifact download) if it's returned
                    zip_data = response.content  # This is the ZIP file returned by upstream

                    # You could also send the file as a download to the user:
                    return send_file(
                        io.BytesIO(zip_data),
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

    # Fetch the list of test procedures for the dropdown
    procedures_url = f"{CACTUS_ORCHESTRATOR_BASEURL}/procedure"
    procedures_response = requests.get(procedures_url, headers=headers)
    procedures = []
    if procedures_response.status_code == 200:
        procedures = procedures_response.json().get("items", [])

    response = requests.get(runs_url, headers=headers)
    if response.status_code == 200:
        runs_data = response.json()
        runs = runs_data.get("items", [])
        next_page = runs_data.get("next", None)
        prev_page = runs_data.get("previous", None)
        total_items = runs_data.get("total", 0)
        page_size = runs_data.get("page_size", 10)
        current_page = runs_data.get("page", 1)

        return render_template(
            "runs.html",
            runs=runs,
            next_page=next_page,
            prev_page=prev_page,
            total_items=total_items,
            page_size=page_size,
            current_page=current_page,
            procedures=procedures,
        )
    else:
        error = "Failed to retrieve runs."
        return render_template("runs.html", error=error)


@app.route("/callback", methods=["GET", "POST"])
def callback() -> Response:
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    return redirect("/runs")


@app.route("/login")
def login() -> str:
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True), audience=CACTUS_ORCHESTRATOR_AUDIENCE
    )


@app.route("/logout")
def logout() -> Response:
    session.clear()
    return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(env.get("PORT", 3000)), debug=True)
