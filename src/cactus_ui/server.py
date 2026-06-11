"""Python Flask WebApp Auth0 integration example"""

import io
import json
import logging
import logging.config
import os
import zipfile
from base64 import b64encode
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime
from functools import lru_cache, wraps
from http import HTTPStatus
from os import environ as env
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote_plus, urlencode

import cactus_schema.orchestrator as schema
import jwt
from authlib.integrations.flask_client import OAuth
from cactus_schema.orchestrator.compliance import fetch_compliance_classes
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
    send_from_directory,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.wrappers.response import Response

import cactus_ui.orchestrator as orchestrator
from cactus_ui.compliance_class import fetch_compliance_class

# Setup logs
logconf_fp = "./logconf.json"
if os.path.exists(logconf_fp):
    with open(logconf_fp) as f:
        logging.config.dictConfig(json.load(f))
else:
    logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)

_WITNESS_CLASSES = frozenset({"DER-A", "DER-G", "DER-L", "DR-D", "DR-G", "DR-L"})
# Integer status codes used by TestProcedureRunSummaryResponse.latest_run_status (not a RunStatusResponse enum)
_ACTIVE_RUN_STATUS_INTS = [1, 2, 6]  # initialised, started, provisioning
_FINALIZED_RUN_STATUS_INTS = [3, 4]  # finalised by user, finalised by timeout
# RunStatusResponse enum values used by RunResponse.status
_ACTIVE_RUN_STATUSES = frozenset(
    {schema.RunStatusResponse.initialised, schema.RunStatusResponse.started, schema.RunStatusResponse.provisioning}
)


def is_witness_test(run_response: schema.RunResponse | None) -> bool:
    return bool(_WITNESS_CLASSES & set(run_response.classes or [])) if run_response else False


ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")
if not (env.get("CACTUS_UI_LOCALDEV", "false").lower() == "true"):
    app.wsgi_app = ProxyFix(app.wsgi_app)  # type: ignore


oauth = OAuth(app)
oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "user:all openid profile email",
    },
    server_metadata_url=f"https://{env.get('AUTH0_DOMAIN')}/.well-known/openid-configuration",
)

# envvars
CACTUS_ORCHESTRATOR_AUDIENCE = env["CACTUS_ORCHESTRATOR_AUDIENCE"]
CACTUS_PLATFORM_VERSION = env["CACTUS_PLATFORM_VERSION"]
CACTUS_PLATFORM_SUPPORT_EMAIL = env["CACTUS_PLATFORM_SUPPORT_EMAIL"]
BANNER_MESSAGE = env.get("BANNER_MESSAGE")
LOGIN_BANNER_MESSAGE = env.get("LOGIN_BANNER_MESSAGE")

# Built React SPA (frontend/dist). Overridable for tests/deployments where dist lives elsewhere.
FRONTEND_DIST_DIR = Path(
    env.get("CACTUS_UI_FRONTEND_DIST", Path(__file__).resolve().parents[2] / "frontend" / "dist")
).resolve()


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
        exp_time = datetime.fromtimestamp(float(user["expires_at"]), tz=UTC)
        if exp_time < datetime.now(tz=UTC):
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


def login_required[F: Callable[..., object]](f: F) -> F:
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        access_token = get_access_token()
        if access_token is None:
            return redirect(url_for("login"))

        return f(*args, access_token=access_token, **kwargs)

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


def admin_role_required[F: Callable[..., object]](f: F) -> F:
    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        permissions = get_permissions()
        if not permissions or "admin:all" not in permissions:
            return redirect(url_for("login_or_home_page"))

        return f(*args, **kwargs)

    return cast(F, decorated)


def api_login_required[F: Callable[..., object]](f: F) -> F:
    """Like login_required, but for /api endpoints: returns 401 JSON instead of redirecting to login."""

    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        access_token = get_access_token()
        if access_token is None:
            return jsonify({"error": "unauthenticated"}), HTTPStatus.UNAUTHORIZED

        return f(*args, access_token=access_token, **kwargs)

    return cast(F, decorated)


def api_admin_role_required[F: Callable[..., object]](f: F) -> F:
    """Like admin_role_required, but for /api endpoints: returns 403 JSON instead of redirecting."""

    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        permissions = get_permissions()
        if not permissions or "admin:all" not in permissions:
            return jsonify({"error": "forbidden"}), HTTPStatus.FORBIDDEN

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


def run_summary_to_compliance_status(
    test_procedure: schema.TestProcedureRunSummaryResponse,
) -> str:
    if test_procedure.latest_run_status in _ACTIVE_RUN_STATUS_INTS:
        return "active"
    elif test_procedure.run_count == 0:
        return "runless"
    elif test_procedure.latest_run_status in _FINALIZED_RUN_STATUS_INTS:
        if test_procedure.latest_all_criteria_met:
            return "success"
        else:
            return "failed"
    else:
        return "unknown"


def build_playlist_tests_by_category(
    procedures: list[schema.TestProcedureRunSummaryResponse],
) -> dict[str, list[dict]]:
    """Build ordered category→tests dict for the playlist builder, excluding immediate_start procedures.

    Procedures are expected to arrive in definition order from the orchestrator; insertion order is preserved.
    """
    result: dict[str, list[dict]] = {}
    for p in procedures:
        if p.immediate_start:
            continue
        cat = p.category
        if cat not in result:
            result[cat] = []
        result[cat].append(
            {
                "id": str(p.test_procedure_id),
                "description": p.description,
                "is_witness": bool(_WITNESS_CLASSES & set(p.classes or [])),
                "classes": p.classes or [],
            }
        )
    return result


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
def login_or_home_page() -> Response:
    return send_file(FRONTEND_DIST_DIR / "index.html")


@app.route("/<path:spa_path>")
def spa_catch_all(spa_path: str) -> Response:
    """Serves built SPA assets, falling back to index.html for client-side routes.

    Only fires for paths not matched by any other route; /api paths must never serve HTML."""
    if spa_path.startswith("api/"):
        return Response(
            response=json.dumps({"error": "not found"}),
            status=HTTPStatus.NOT_FOUND,
            mimetype="application/json",
        )

    if (FRONTEND_DIST_DIR / spa_path).is_file():
        return send_from_directory(FRONTEND_DIST_DIR, spa_path)

    return send_file(FRONTEND_DIST_DIR / "index.html")


@app.route("/api/session", methods=["GET"])
def api_session() -> Response | tuple[Response, int]:
    """Session/global context for the SPA (replaces the Jinja context processor).

    Returns 401 with the login banner message when not logged in - the SPA shows the login screen."""
    access_token = get_access_token()
    if access_token is None:
        return (
            jsonify({"error": "unauthenticated", "login_banner_message": LOGIN_BANNER_MESSAGE}),
            HTTPStatus.UNAUTHORIZED,
        )

    return jsonify(
        {
            "username": get_username_from_session(),
            "permissions": get_permissions() or [],
            "version": CACTUS_PLATFORM_VERSION,
            "support_email": CACTUS_PLATFORM_SUPPORT_EMAIL,
            "banner_message": BANNER_MESSAGE,
            "hosted_images": [f"/{path}" for path in get_hosted_images()],
        }
    )


@app.route("/admin")
@login_required
@admin_role_required
def admin_page(access_token: str) -> str:
    users = orchestrator.admin_fetch_users(access_token)
    if users is None:
        return render_template("admin.html", error="Failed to retrieve users.")

    def custom_serializer(obj: Any) -> str | dict:  # noqa: ANN401
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


@app.route("/admin/stats")
@login_required
@admin_role_required
def admin_stats_page(access_token: str) -> str:
    stats = orchestrator.admin_fetch_stats(access_token)
    if stats is None:
        return render_template("admin_stats.html", error="Failed to retrieve stats.")

    # Convert runs_per_user dict to sorted leaderboard list for the template
    user_leaderboard = [
        {"name": name, "run_count": count}
        for name, count in sorted(stats.runs_per_user.items(), key=lambda x: x[1], reverse=True)
    ]

    # Build weekly bars; x-axis label shows month only when it changes
    week_bars: list[dict] = []
    last_month: str | None = None
    last_year: str | None = None
    for week_str, count in sorted(stats.runs_per_week.items()):
        try:
            yr_s, wk_s = week_str.split("-W")
            dt = datetime.strptime(f"{yr_s}-W{int(wk_s):02d}-1", "%G-W%V-%u")
            month_key = dt.strftime("%b %Y")
            month_display = dt.strftime("%b")
            year_display = dt.strftime("%Y")
        except (ValueError, AttributeError):
            month_key = week_str
            month_display = week_str
            year_display = ""
        week_bars.append(
            {
                "month": month_display if month_key != last_month else "",
                "year": year_display if year_display != last_year else "",
                "count": count,
            }
        )
        last_month = month_key
        last_year = year_display

    # Sort procedures by total_runs descending (all procedures are returned, not just top 20)
    procedures = sorted(stats.procedures, key=lambda p: p.get("total_runs", 0), reverse=True)

    return render_template(
        "admin_stats.html",
        total_users=stats.total_users,
        total_run_groups=stats.total_run_groups,
        total_runs=stats.total_runs,
        total_passed=stats.total_passed,
        total_failed=stats.total_failed,
        version_counts=stats.version_counts,
        user_leaderboard=user_leaderboard,
        procedures=procedures,
        max_run_number=stats.max_run_id,
        runs_per_week=week_bars,
    )


@app.route("/admin/group/<int:run_group_id>", methods=["GET", "POST"])
@login_required
@admin_role_required
def admin_run_group_page(  # noqa: C901
    access_token: str, run_group_id: int
) -> str | Response:
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
                {
                    "procedure": procedure_map[t],
                    "status": run_summary_to_compliance_status(procedure_map[t]),
                }
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

    run_is_live = status is not None or (run_response is not None and run_response.status in _ACTIVE_RUN_STATUSES)

    # Take the big JSON response string and encode it using base64 so we can embed it in the template and re-hydrate
    # it easily enough
    if status is not None:
        initial_status_b64 = b64encode(status.encode()).decode()
    else:
        initial_status_b64 = ""

    playlist_info, next_playlist_run_id, current_active_run = (
        _build_playlist_info(access_token, run_response, admin=True) if run_response else (None, None, None)
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
        is_admin_view=True,
        is_witness_test=is_witness_test(run_response),
        user_buttons_state="disabled",
        proceed_uri=url_for("admin_send_proceed", run_id=run_id),
        cactus_platform_support_email=CACTUS_PLATFORM_SUPPORT_EMAIL,
    )


def _parse_video_start(raw: str | None) -> float | None:
    """Parse a video timestamp string ('SS', 'M:SS', 'MM:SS', 'H:MM:SS') to seconds.

    Returns None if the input is absent, empty, or cannot be parsed — callers treat
    None as "no offset" and generate the chart with the default test-relative axis.
    """
    if not raw:
        return None
    parts = raw.strip().split(":")
    try:
        nums = [float(p) for p in parts]
    except ValueError:
        return None
    if len(nums) == 1:
        return nums[0]
    if len(nums) == 2:
        return nums[0] * 60 + nums[1]
    if len(nums) == 3:
        return nums[0] * 3600 + nums[1] * 60 + nums[2]
    return None


@app.route("/admin/run/<int:run_id>/html_report", methods=["GET"])
@login_required
@admin_role_required
def admin_run_html_report_page(access_token: str, run_id: int) -> str | Response:
    video_start = _parse_video_start(request.args.get("video_start"))
    html = orchestrator.admin_fetch_run_power_limit_chart(access_token, run_id, video_start_seconds=video_start)
    if html is None:
        return Response(response="Failed to generate HTML report.", status=HTTPStatus.BAD_GATEWAY)
    return Response(html, mimetype="text/html")


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


@app.route("/api/procedures", methods=["GET"])
@api_login_required
def api_procedures(access_token: str) -> Response | tuple[Response, int]:
    """Get all test procedures, handling pagination."""
    all_procedures = []
    page = 1

    while True:
        procedure_pages = orchestrator.fetch_procedures(access_token, page)
        if procedure_pages is None:
            return jsonify({"error": "Failed to retrieve procedures."}), HTTPStatus.BAD_GATEWAY

        all_procedures.extend(procedure_pages.items)

        if procedure_pages.next_page is None:
            break

        page = procedure_pages.next_page

    return jsonify({"procedures": [p.to_dict() for p in all_procedures]})


@app.route("/api/procedure/<test_procedure_id>", methods=["GET"])
@api_login_required
def api_procedure_yaml(access_token: str, test_procedure_id: str) -> Response | tuple[Response, int]:
    """Get the raw YAML definition for a single test procedure."""
    yaml = orchestrator.fetch_procedure_yaml(access_token, test_procedure_id)
    if yaml is None:
        return jsonify({"error": f"Failed to fetch YAML for test '{test_procedure_id}'."}), HTTPStatus.BAD_GATEWAY

    return jsonify({"test_procedure_id": test_procedure_id, "yaml": yaml})


def paginated_json(page: schema.Pagination) -> dict:
    """Serialise a Pagination of JSONWizard items to a plain dict (snake_case keys, ISO datetimes)."""
    return {
        "total_pages": page.total_pages,
        "total_items": page.total_items,
        "page_size": page.page_size,
        "current_page": page.current_page,
        "prev_page": page.prev_page,
        "next_page": page.next_page,
        "items": [item.to_dict() for item in page.items],
    }


def build_procedure_summaries_json(procedures: list[schema.TestProcedureRunSummaryResponse]) -> dict:
    """Groups procedure run summaries by category (preserving order) with compliance class filter maps."""
    grouped: dict[str, dict] = {}  # slug -> group, insertion ordered
    all_classes: set[str] = set()
    classes_by_test: dict[str, list[str]] = {}
    classes_by_category: dict[str, set[str]] = {}

    for p in procedures:
        category_slug = p.category.replace(" ", "-")  # This could do with a more robust slugify method

        group = grouped.setdefault(category_slug, {"slug": category_slug, "category": p.category, "summaries": []})
        group["summaries"].append(p.to_dict())

        classes = p.classes if p.classes else []
        classes_by_test[p.test_procedure_id] = classes
        all_classes.update(classes)
        classes_by_category.setdefault(category_slug, set()).update(classes)

    return {
        "grouped_procedures": list(grouped.values()),
        "classes": [{"name": c.name, "description": c.description} for c in fetch_compliance_classes(all_classes)],
        "classes_by_test": classes_by_test,
        "classes_by_category": {key: sorted(value) for key, value in classes_by_category.items()},
    }


@app.route("/api/run_groups", methods=["GET"])
@api_login_required
def api_run_groups(access_token: str) -> Response | tuple[Response, int]:
    """Run groups for the current user (page 1 - matches the old template's dropdown source)."""
    run_groups = orchestrator.fetch_run_groups(access_token, 1)
    if run_groups is None:
        return jsonify({"error": "Unable to fetch run groups."}), HTTPStatus.BAD_GATEWAY

    return jsonify(paginated_json(run_groups))


@app.route("/api/admin/run_groups", methods=["GET"])
@api_login_required
@api_admin_role_required
def api_admin_run_groups(access_token: str) -> Response | tuple[Response, int]:
    """Run groups belonging to the user that owns ?run_group_id (admins can't be identified by token alone)."""
    run_group_id = request.args.get("run_group_id", type=int)
    if run_group_id is None:
        return jsonify({"error": "run_group_id is required."}), HTTPStatus.BAD_REQUEST

    run_groups = orchestrator.admin_fetch_run_groups(access_token, run_group_id, 1)
    if run_groups is None:
        return jsonify({"error": "Unable to fetch run groups."}), HTTPStatus.BAD_GATEWAY

    return jsonify(paginated_json(run_groups))


@app.route("/api/group/<int:run_group_id>/procedure_summaries", methods=["GET"])
@api_login_required
def api_group_procedure_summaries(access_token: str, run_group_id: int) -> Response | tuple[Response, int]:
    procedures = orchestrator.fetch_group_procedure_run_summaries(access_token, run_group_id)
    if procedures is None:
        return jsonify({"error": "Unable to fetch test procedures."}), HTTPStatus.BAD_GATEWAY

    return jsonify(build_procedure_summaries_json(procedures))


@app.route("/api/admin/group/<int:run_group_id>/procedure_summaries", methods=["GET"])
@api_login_required
@api_admin_role_required
def api_admin_group_procedure_summaries(access_token: str, run_group_id: int) -> Response | tuple[Response, int]:
    procedures = orchestrator.admin_fetch_group_procedure_run_summaries(
        access_token=access_token, run_group_id=run_group_id
    )
    if procedures is None:
        return jsonify({"error": "Unable to fetch test procedures."}), HTTPStatus.BAD_GATEWAY

    return jsonify(build_procedure_summaries_json(procedures))


@app.route("/api/group/<int:run_group_id>/procedure_runs/<test_procedure_id>", methods=["GET"])
@api_login_required
def api_group_procedure_runs(
    access_token: str, run_group_id: int, test_procedure_id: str
) -> Response | tuple[Response, int]:
    runs_page = orchestrator.fetch_group_runs_for_procedure(access_token, run_group_id, test_procedure_id)
    if runs_page is None:
        return jsonify({"error": f"Unable to fetch runs for {test_procedure_id}."}), HTTPStatus.BAD_GATEWAY

    return jsonify(paginated_json(runs_page))


@app.route("/api/admin/group/<int:run_group_id>/procedure_runs/<test_procedure_id>", methods=["GET"])
@api_login_required
@api_admin_role_required
def api_admin_group_procedure_runs(
    access_token: str, run_group_id: int, test_procedure_id: str
) -> Response | tuple[Response, int]:
    runs_page = orchestrator.admin_fetch_group_runs_for_procedure(access_token, run_group_id, test_procedure_id)
    if runs_page is None:
        return jsonify({"error": f"Unable to fetch runs for {test_procedure_id}."}), HTTPStatus.BAD_GATEWAY

    return jsonify(paginated_json(runs_page))


@app.route("/api/group/<int:run_group_id>/active_runs", methods=["GET"])
@api_login_required
def api_group_active_runs(access_token: str, run_group_id: int) -> Response | tuple[Response, int]:
    runs_page = orchestrator.fetch_runs_for_group(access_token, run_group_id, 1, False)
    if runs_page is None:
        return jsonify({"error": "Unable to load active runs."}), HTTPStatus.BAD_GATEWAY

    return jsonify(paginated_json(runs_page))


@app.route("/api/admin/group/<int:run_group_id>/active_runs", methods=["GET"])
@api_login_required
@api_admin_role_required
def api_admin_group_active_runs(access_token: str, run_group_id: int) -> Response | tuple[Response, int]:
    runs_page = orchestrator.admin_fetch_runs_for_group(access_token, run_group_id, 1, False)
    if runs_page is None:
        return jsonify({"error": "Unable to load active runs."}), HTTPStatus.BAD_GATEWAY

    return jsonify(paginated_json(runs_page))


@app.route("/api/group/<int:run_group_id>/runs", methods=["POST"])
@api_login_required
def api_init_run(access_token: str, run_group_id: int) -> Response | tuple[Response, int]:
    """Initialise a new test run (the precondition phase) for a test procedure."""
    body = request.get_json(silent=True) or {}
    test_procedure_id = body.get("test_procedure_id")
    if not test_procedure_id:
        return jsonify({"error": "No test procedure selected."}), HTTPStatus.BAD_REQUEST

    init_result = orchestrator.init_run(access_token, run_group_id, test_procedure_id)
    if init_result.response is not None:
        return jsonify({"run_id": init_result.response.run_id})
    elif init_result.failure_type == orchestrator.InitialiseRunFailureType.EXPIRED_CERT:
        return (
            jsonify({"error": "Your certificate has expired. Please generate and download a new certificate."}),
            HTTPStatus.CONFLICT,
        )
    elif init_result.failure_type == orchestrator.InitialiseRunFailureType.EXISTING_STATIC_INSTANCE:
        return (
            jsonify({"error": "You cannot start a second test run while your DeviceCapability URI is set to static."}),
            HTTPStatus.CONFLICT,
        )
    else:
        return jsonify({"error": "Failed to trigger a new run due to an unknown error."}), HTTPStatus.BAD_GATEWAY


@app.route("/api/runs/<int:run_id>/start", methods=["POST"])
@api_login_required
def api_start_run(access_token: str, run_id: int) -> Response | tuple[Response, int]:
    start_result = orchestrator.start_run(access_token, str(run_id))
    if not start_result.success:
        error = "Failed to start the test run." if start_result.error_message is None else start_result.error_message
        return jsonify({"error": error}), HTTPStatus.BAD_GATEWAY

    return jsonify({"run_id": run_id})


@app.route("/api/runs/<int:run_id>/finalise", methods=["POST"])
@api_login_required
def api_finalise_run(access_token: str, run_id: int) -> Response | tuple[Response, int]:
    if not orchestrator.finalise_run(access_token, str(run_id)):
        return jsonify({"error": "Failed to finalise the run."}), HTTPStatus.BAD_GATEWAY

    return jsonify({"run_id": run_id})


@app.route("/api/runs/<int:run_id>", methods=["DELETE"])
@api_login_required
def api_delete_run(access_token: str, run_id: int) -> Response | tuple[Response, int]:
    if not orchestrator.delete_individual_run(access_token, str(run_id)):
        return jsonify({"error": "Failed to delete run."}), HTTPStatus.BAD_GATEWAY

    return jsonify({"run_id": run_id})


@app.route("/run/<int:run_id>/artifact", methods=["GET"])
@login_required
def run_artifact_download(access_token: str, run_id: int) -> Response:
    """Browser-native artifact ZIP download (plain link; session cookie auth)."""
    artifact_data, download_name = orchestrator.fetch_run_artifact(access_token, str(run_id))
    if artifact_data is None:
        return Response(response="Failed to retrieve artifacts.", status=HTTPStatus.BAD_GATEWAY, mimetype="text/plain")

    return send_file(
        io.BytesIO(artifact_data),
        as_attachment=True,
        download_name=download_name,
        mimetype="application/zip",
    )


@app.route("/admin/run/<int:run_id>/artifact", methods=["GET"])
@login_required
@admin_role_required
def admin_run_artifact_download(access_token: str, run_id: int) -> Response:
    """Browser-native artifact ZIP download for the admin view."""
    artifact_data, download_name = orchestrator.admin_fetch_run_artifact(access_token, str(run_id))
    if artifact_data is None:
        return Response(response="Failed to retrieve artifacts.", status=HTTPStatus.BAD_GATEWAY, mimetype="text/plain")

    return send_file(
        io.BytesIO(artifact_data),
        as_attachment=True,
        download_name=download_name,
        mimetype="application/zip",
    )


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
                    io.BytesIO(download_bytes),
                    "application/x-x509-user-cert",
                    True,
                    download_name=download_file_name,
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
                return send_file(
                    io.BytesIO(download_bytes),
                    "application/zip",
                    True,
                    download_name=download_file_name,
                )

        elif action == "generatedevice" or action == "generateagg":
            run_group_id = int(request.form.get("run_group_id", ""))
            download_bytes, download_file_name = orchestrator.generate_client_cert(
                access_token, run_group_id, action == "generatedevice"
            )
            if not download_bytes or not download_file_name:
                error = "Failed to generate certificate for run group."
            else:
                return send_file(
                    io.BytesIO(download_bytes),
                    "application/zip",
                    True,
                    download_name=download_file_name,
                )

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
        ),  # A PEN of 0 is reserved. Replace with "" to trigger display of placeholder text
    )


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
                {
                    "procedure": procedure_map[t],
                    "status": run_summary_to_compliance_status(procedure_map[t]),
                }
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
    procedures_raw = request.form.get("procedures", "")
    if not procedures_raw:
        return "No tests selected."

    try:
        procedures = json.loads(procedures_raw)
    except (json.JSONDecodeError, ValueError):
        return "Invalid test selection."

    if not procedures or not isinstance(procedures, list):
        return "No tests selected."

    init_result = orchestrator.init_playlist(access_token, run_group_id, procedures, 0)
    if init_result.response is not None:
        if init_result.response.playlist_execution_id and init_result.response.playlist_runs:
            session["active_playlist"] = {
                "execution_id": init_result.response.playlist_execution_id,
                "name": "Custom Playlist",
                "started_at": datetime.now(UTC).isoformat(),
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
    """Page for building and starting playlists"""
    error: str | None = None

    if request.method == "POST":
        result = _handle_playlists_post(access_token, run_group_id)
        if isinstance(result, Response):
            return result
        if isinstance(result, str):
            error = result

    procedures = orchestrator.fetch_group_procedure_run_summaries(access_token, run_group_id)
    if procedures is None:
        error = "Unable to fetch test procedures."

    all_classes: set[str] = set()
    for p in procedures or []:
        if p.classes:
            all_classes.update(p.classes)

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
        tests_by_category=build_playlist_tests_by_category(procedures or []),
        classes=fetch_compliance_classes(all_classes),
        run_groups=[] if run_groups is None else run_groups.items,
        run_group_id=run_group_id,
        active_run_group=active_run_group,
    )


@app.route("/group/<int:run_group_id>/past_playlist_sessions", methods=["GET"])
@login_required
def past_playlist_sessions_json(access_token: str, run_group_id: int) -> Response:
    """Fetch all playlist sessions (active and completed) grouped by execution ID."""
    all_runs_page = orchestrator.fetch_runs_for_group(access_token, run_group_id, 1, None)
    if all_runs_page is None:
        return Response(response=json.dumps([]), status=HTTPStatus.OK, mimetype="application/json")

    active_statuses = {"initialised", "started", "provisioning"}

    playlist_executions: dict[str, list[schema.RunResponse]] = {}
    for run in all_runs_page.items:
        if run.playlist_execution_id:
            playlist_executions.setdefault(run.playlist_execution_id, []).append(run)

    result = []
    for exec_id, runs in playlist_executions.items():
        runs_sorted = sorted(runs, key=lambda r: r.playlist_order or 0)
        if not runs_sorted:
            continue
        first_run = runs_sorted[0]
        is_active = any(
            (r.status.value if hasattr(r.status, "value") else str(r.status)) in active_statuses for r in runs_sorted
        )
        result.append(
            {
                "playlist_execution_id": exec_id,
                "short_id": exec_id[:8],
                "first_run_id": first_run.run_id,
                "created_at": first_run.created_at.isoformat(),
                "test_statuses": [build_test_status_dict(r) for r in runs_sorted],
                "is_active": is_active,
            }
        )

    # Active sessions first, then most recent
    result.sort(key=lambda x: str(x["created_at"]), reverse=True)
    result.sort(key=lambda x: not bool(x["is_active"]))

    return Response(response=json.dumps(result), status=HTTPStatus.OK, mimetype="application/json")


def _build_playlist_info(
    access_token: str, run_response: schema.RunResponse, admin: bool = False
) -> tuple[dict | None, int | None, dict | None]:
    """Build playlist template context from a run that belongs to a playlist.

    Returns (playlist_info, next_playlist_run_id, current_active_run).
    """
    if not run_response.playlist_runs:
        return None, None, None

    fetch_run = orchestrator.admin_fetch_individual_run if admin else orchestrator.fetch_individual_run
    current_order = run_response.playlist_order
    active_playlist_session = session.get("active_playlist", {})

    playlist_runs_full: list[dict] = []
    first_run_started_at = None
    for i, r in enumerate(run_response.playlist_runs):
        full_run = fetch_run(access_token, str(r.run_id))
        if full_run:
            if i == 0:
                first_run_started_at = full_run.created_at.isoformat() if full_run.created_at else None
            playlist_runs_full.append(build_test_status_dict(full_run))
        else:
            playlist_runs_full.append(
                {
                    "run_id": r.run_id,
                    "test_procedure_id": r.test_procedure_id,
                    "status": (r.status.value if hasattr(r.status, "value") else str(r.status)),
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
        if not orchestrator.finalise_run(access_token, run_id):
            return "Failed to finalise the run."
        return None
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


@app.route("/run/<int:run_id>/html_report", methods=["GET"])
@login_required
def run_html_report_page(access_token: str, run_id: int) -> str | Response:
    video_start = _parse_video_start(request.args.get("video_start"))
    html, error_detail = orchestrator.fetch_run_power_limit_chart(access_token, run_id, video_start_seconds=video_start)
    if html is None:
        message = error_detail or "Failed to generate HTML report."
        return Response(response=message, status=HTTPStatus.BAD_GATEWAY)
    return Response(html, mimetype="text/html")


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

    run_is_live = status is not None or (run_response is not None and run_response.status in _ACTIVE_RUN_STATUSES)

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
        is_admin_view=False,
        is_witness_test=is_witness_test(run_response),
        proceed_uri=url_for("send_proceed", run_id=run_id),
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
        return Response(
            response="Failed to proceed to next step",
            status=HTTPStatus.INTERNAL_SERVER_ERROR,
        )

    return Response(
        response=proceed_response.to_json(),
        status=HTTPStatus.OK,
        mimetype="application/json",
    )


@app.route("/admin/run/<int:run_id>/proceed", methods=["GET"])
@login_required
@admin_role_required
def admin_send_proceed(access_token: str, run_id: str) -> Response:

    proceed_response = orchestrator.admin_send_proceed(access_token=access_token, run_id=run_id)

    if proceed_response is None:
        return Response(
            response="Failed to proceed to next step",
            status=HTTPStatus.INTERNAL_SERVER_ERROR,
        )

    return Response(
        response=proceed_response.to_json(),
        status=HTTPStatus.OK,
        mimetype="application/json",
    )


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
        redirect_uri=url_for("callback", _external=True),
        audience=CACTUS_ORCHESTRATOR_AUDIENCE,
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
    app.run(
        host="127.0.0.1",
        port=int(env.get("PORT", 3000)),
        debug=True,  # noqa: S201  # nosec B201 - not for deployment
    )
