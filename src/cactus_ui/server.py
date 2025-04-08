"""Python Flask WebApp Auth0 integration example"""

from os import environ as env
from urllib.parse import quote_plus, urlencode
import requests

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for
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


@app.route("/run")
def run() -> str:
    resp = requests.get(CACTUS_ORCHESTRATOR_BASEURL + "/run" , headers={"Authorization": f"Bearer {session["user"]["access_token"]}"})
    return render_template("run.html", run=resp.json()["items"])


@app.route("/callback", methods=["GET", "POST"])
def callback() -> Response:
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    return redirect("/run")


@app.route("/login")
def login() -> str:
    return oauth.auth0.authorize_redirect(redirect_uri=url_for("callback", _external=True), audience=CACTUS_ORCHESTRATOR_AUDIENCE)


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
    app.run(host="0.0.0.0", port=int(env.get("PORT", 3000)))
