"""Python Flask WebApp Auth0 integration example"""

import io
import json
import logging
import logging.config
import os
import zipfile
from datetime import UTC, datetime
from functools import lru_cache
from http import HTTPStatus
from os import environ as env
from pathlib import Path
from urllib.parse import quote_plus, urlencode

import cactus_schema.orchestrator as schema
from authlib.integrations.flask_client import OAuth
from cactus_schema.orchestrator.compliance import fetch_compliance_classes
from dotenv import find_dotenv, load_dotenv
from flask import (
    Flask,
    current_app,
    jsonify,
    redirect,
    request,
    send_file,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.wrappers.response import Response

import cactus_ui.orchestrator as orchestrator
from cactus_ui.api_models import (
    AdminStatsResponse,
    AdminUserResponse,
    AdminUsersResponse,
    ConfigResponse,
    PlaylistSession,
    PlaylistTestsResponse,
    ProceduresResponse,
    ProcedureStat,
    ProcedureYamlResponse,
    RunActionResponse,
    RunStatusShell,
    SessionResponse,
    UserConfig,
    UserLeaderboardEntry,
    WeekBar,
)
from cactus_ui.auth import (
    admin_role_required,
    api_admin_role_required,
    api_login_required,
    get_access_token,
    get_permissions,
    get_username_from_session,
    login_required,
)
from cactus_ui.presenters import (
    build_compliance,
    build_playlist_tests_by_category,
    build_procedure_summaries,
    build_test_status,
    paginated_json,
)

# Setup logs
logconf_fp = "./logconf.json"
if os.path.exists(logconf_fp):
    with open(logconf_fp) as f:
        logging.config.dictConfig(json.load(f))
else:
    logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)

# Test procedures with `immediate_start: true` - these have no init phase and so no meaningful
# active-power timeline, so the run status page hides the Active Power Chart for them.
# INTERIM: hardcoded mirror of the cactus-test-definitions client procedures (same hardcoded
# pattern as presenters._WITNESS_CLASSES). The clean fix is an additive `immediate_start` field
# on the orchestrator's RunResponse; swap is_immediate_start() to read that when it lands.
_IMMEDIATE_START_PROCEDURE_IDS = frozenset(
    {
        "ALL-01",
        "ALL-02",
        "ALL-03",
        "ALL-03-REJ",
        "ALL-04",
        "ALL-05",
        "ALL-06",
        "ALL-09",
        "ALL-14",
        "DRA-01",
        "MUL-03",
        "STO-02",
    }
)
# RunStatusResponse enum values used by RunResponse.status
_ACTIVE_RUN_STATUSES = frozenset(
    {schema.RunStatusResponse.initialised, schema.RunStatusResponse.started, schema.RunStatusResponse.provisioning}
)


def is_immediate_start(run_response: schema.RunResponse | None) -> bool:
    return bool(run_response and run_response.test_procedure_id in _IMMEDIATE_START_PROCEDURE_IDS)


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
        SessionResponse(
            username=get_username_from_session(),
            permissions=get_permissions() or [],
            version=CACTUS_PLATFORM_VERSION,
            support_email=CACTUS_PLATFORM_SUPPORT_EMAIL,
            banner_message=BANNER_MESSAGE,
            hosted_images=[f"/{path}" for path in get_hosted_images()],
        ).to_dict()
    )


@app.route("/api/admin/stats", methods=["GET"])
@api_login_required
@api_admin_role_required
def api_admin_stats(access_token: str) -> Response | tuple[Response, int]:
    stats = orchestrator.admin_fetch_stats(access_token)
    if stats is None:
        return jsonify({"error": "Failed to retrieve stats."}), HTTPStatus.BAD_GATEWAY

    user_leaderboard = [
        UserLeaderboardEntry(name=name, run_count=count)
        for name, count in sorted(stats.runs_per_user.items(), key=lambda x: x[1], reverse=True)
    ]

    week_bars: list[WeekBar] = []
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
            WeekBar(
                month=month_display if month_key != last_month else "",
                year=year_display if year_display != last_year else "",
                count=count,
            )
        )
        last_month = month_key
        last_year = year_display

    procedures = [
        ProcedureStat.from_dict(p) for p in sorted(stats.procedures, key=lambda p: p.get("total_runs", 0), reverse=True)
    ]

    return jsonify(
        AdminStatsResponse(
            total_users=stats.total_users,
            total_run_groups=stats.total_run_groups,
            total_runs=stats.total_runs,
            total_passed=stats.total_passed,
            total_failed=stats.total_failed,
            max_run_number=stats.max_run_id,
            version_counts=stats.version_counts,
            user_leaderboard=user_leaderboard,
            procedures=procedures,
            runs_per_week=week_bars,
        ).to_dict()
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

    return jsonify(ProceduresResponse(procedures=all_procedures).to_dict())


@app.route("/api/procedure/<test_procedure_id>", methods=["GET"])
@api_login_required
def api_procedure_yaml(access_token: str, test_procedure_id: str) -> Response | tuple[Response, int]:
    """Get the raw YAML definition for a single test procedure."""
    yaml = orchestrator.fetch_procedure_yaml(access_token, test_procedure_id)
    if yaml is None:
        return jsonify({"error": f"Failed to fetch YAML for test '{test_procedure_id}'."}), HTTPStatus.BAD_GATEWAY

    return jsonify(ProcedureYamlResponse(test_procedure_id=test_procedure_id, yaml=yaml).to_dict())


@app.route("/api/run_groups", methods=["GET"])
@api_login_required
def api_run_groups(access_token: str) -> Response | tuple[Response, int]:
    """Run groups for the current user (page 1 - matches the old template's dropdown source)."""
    run_groups = orchestrator.fetch_run_groups(access_token, 1)
    if run_groups is None:
        return jsonify({"error": "Unable to fetch run groups."}), HTTPStatus.BAD_GATEWAY

    return jsonify(paginated_json(run_groups))


@app.route("/api/admin/users", methods=["GET"])
@api_login_required
@api_admin_role_required
def api_admin_users(access_token: str) -> Response | tuple[Response, int]:
    """All users with their run groups."""
    users = orchestrator.admin_fetch_users(access_token)
    if users is None:
        return jsonify({"error": "Unable to fetch users."}), HTTPStatus.BAD_GATEWAY

    users_list = []
    for user in users:
        matchable_description = orchestrator.get_matchable_description(user.to_dict())
        users_list.append(
            AdminUserResponse(
                user_id=user.user_id,
                subject_id=user.subject_id,
                name=user.name,
                run_groups=user.run_groups,
                matchable_description=matchable_description,
            )
        )

    return jsonify(AdminUsersResponse(users=users_list).to_dict())


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

    return jsonify(build_procedure_summaries(procedures).to_dict())


@app.route("/api/admin/group/<int:run_group_id>/procedure_summaries", methods=["GET"])
@api_login_required
@api_admin_role_required
def api_admin_group_procedure_summaries(access_token: str, run_group_id: int) -> Response | tuple[Response, int]:
    procedures = orchestrator.admin_fetch_group_procedure_run_summaries(
        access_token=access_token, run_group_id=run_group_id
    )
    if procedures is None:
        return jsonify({"error": "Unable to fetch test procedures."}), HTTPStatus.BAD_GATEWAY

    return jsonify(build_procedure_summaries(procedures).to_dict())


@app.route("/api/group/<int:run_group_id>/compliance", methods=["GET"])
@api_login_required
def api_group_compliance(access_token: str, run_group_id: int) -> Response | tuple[Response, int]:
    procedures = orchestrator.fetch_group_procedure_run_summaries(access_token, run_group_id)
    if procedures is None:
        return jsonify({"error": "Unable to fetch test procedures."}), HTTPStatus.BAD_GATEWAY
    return jsonify(build_compliance(procedures).to_dict())


@app.route("/api/admin/group/<int:run_group_id>/compliance", methods=["GET"])
@api_login_required
@api_admin_role_required
def api_admin_group_compliance(access_token: str, run_group_id: int) -> Response | tuple[Response, int]:
    procedures = orchestrator.admin_fetch_group_procedure_run_summaries(
        access_token=access_token, run_group_id=run_group_id
    )
    if procedures is None:
        return jsonify({"error": "Unable to fetch test procedures."}), HTTPStatus.BAD_GATEWAY
    return jsonify(build_compliance(procedures).to_dict())


@app.route("/admin/group/<int:run_group_id>/compliance_pdf", methods=["GET"])
@login_required
@admin_role_required
def admin_compliance_pdf(access_token: str, run_group_id: int) -> Response:
    """Browser-native compliance PDF download for the admin view."""
    compliance_report = orchestrator.admin_fetch_run_group_artifact(access_token, run_group_id)
    if compliance_report is None:
        return Response(
            response="There was an error generating the compliance report.",
            status=HTTPStatus.BAD_GATEWAY,
            mimetype="text/plain",
        )
    return send_file(
        io.BytesIO(compliance_report),
        as_attachment=True,
        download_name=f"{run_group_id}_compliance.pdf",
        mimetype="application/pdf",
    )


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
        return jsonify(RunActionResponse(run_id=init_result.response.run_id).to_dict())
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

    return jsonify(RunActionResponse(run_id=run_id).to_dict())


@app.route("/api/runs/<int:run_id>/finalise", methods=["POST"])
@api_login_required
def api_finalise_run(access_token: str, run_id: int) -> Response | tuple[Response, int]:
    if not orchestrator.finalise_run(access_token, str(run_id)):
        return jsonify({"error": "Failed to finalise the run."}), HTTPStatus.BAD_GATEWAY

    return jsonify(RunActionResponse(run_id=run_id).to_dict())


@app.route("/api/runs/<int:run_id>", methods=["DELETE"])
@api_login_required
def api_delete_run(access_token: str, run_id: int) -> Response | tuple[Response, int]:
    if not orchestrator.delete_individual_run(access_token, str(run_id)):
        return jsonify({"error": "Failed to delete run."}), HTTPStatus.BAD_GATEWAY

    return jsonify(RunActionResponse(run_id=run_id).to_dict())


@app.route("/api/group/<int:run_group_id>/playlist_tests", methods=["GET"])
@api_login_required
def api_playlist_tests(access_token: str, run_group_id: int) -> Response | tuple[Response, int]:
    """Returns tests-by-category and compliance classes for the playlist builder."""
    procedures = orchestrator.fetch_group_procedure_run_summaries(access_token, run_group_id)
    if procedures is None:
        return jsonify({"error": "Unable to fetch test procedures."}), HTTPStatus.BAD_GATEWAY

    all_classes: set[str] = set()
    for p in procedures:
        if p.classes:
            all_classes.update(p.classes)

    return jsonify(
        PlaylistTestsResponse(
            tests_by_category=build_playlist_tests_by_category(procedures),
            classes=list(fetch_compliance_classes(all_classes)),
        ).to_dict()
    )


@app.route("/api/group/<int:run_group_id>/playlist", methods=["POST"])
@api_login_required
def api_init_playlist(access_token: str, run_group_id: int) -> Response | tuple[Response, int]:
    """Initialise a playlist of test runs. Also persists active_playlist in the Flask session for run_status.html."""
    body = request.get_json(silent=True) or {}
    procedures = body.get("procedures")
    if not procedures or not isinstance(procedures, list):
        return jsonify({"error": "No tests selected."}), HTTPStatus.BAD_REQUEST

    init_result = orchestrator.init_playlist(access_token, run_group_id, procedures)
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
        return jsonify(RunActionResponse(run_id=init_result.response.run_id).to_dict())
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
        return jsonify({"error": "Failed to trigger playlist due to an unknown error."}), HTTPStatus.BAD_GATEWAY


@app.route("/api/group/<int:run_group_id>/playlist_sessions", methods=["GET"])
@api_login_required
def api_playlist_sessions(access_token: str, run_group_id: int) -> Response:
    """Fetch all playlist sessions (active and completed) grouped by execution ID."""
    all_runs_page = orchestrator.fetch_runs_for_group(access_token, run_group_id, 1, None)
    if all_runs_page is None:
        return jsonify([])

    active_statuses = {"initialised", "started", "provisioning"}

    playlist_executions: dict[str, list[schema.RunResponse]] = {}
    for run in all_runs_page.items:
        if run.playlist_execution_id:
            playlist_executions.setdefault(run.playlist_execution_id, []).append(run)

    result: list[PlaylistSession] = []
    for exec_id, runs in playlist_executions.items():
        runs_sorted = sorted(runs, key=lambda r: r.playlist_order or 0)
        if not runs_sorted:
            continue
        first_run = runs_sorted[0]
        is_active = any(
            (r.status.value if hasattr(r.status, "value") else str(r.status)) in active_statuses for r in runs_sorted
        )
        result.append(
            PlaylistSession(
                playlist_execution_id=exec_id,
                short_id=exec_id[:8],
                first_run_id=first_run.run_id,
                created_at=first_run.created_at.isoformat(),
                test_statuses=[build_test_status(r) for r in runs_sorted],
                is_active=is_active,
            )
        )

    result.sort(key=lambda x: x.created_at, reverse=True)
    result.sort(key=lambda x: not x.is_active)

    return jsonify([s.to_dict() for s in result])


@app.route("/api/runs/<int:run_id>/finalise_playlist", methods=["POST"])
@api_login_required
def api_finalise_playlist(access_token: str, run_id: int) -> Response:
    """Finalise a playlist early: finalises current test and marks remaining as skipped."""
    orchestrator.finalise_playlist(access_token, str(run_id))
    return jsonify(RunActionResponse(run_id=run_id).to_dict())


@app.route("/api/config", methods=["GET"])
@api_login_required
def api_config(access_token: str) -> Response | tuple[Response, int]:
    config = orchestrator.fetch_config(access_token)
    run_groups = orchestrator.fetch_run_groups(access_token, 1)
    csip_aus_versions = orchestrator.fetch_csip_aus_versions(access_token, 1)
    if config is None or run_groups is None or csip_aus_versions is None:
        return jsonify({"error": "Unable to communicate with test server."}), HTTPStatus.BAD_GATEWAY
    return jsonify(
        ConfigResponse(
            config=UserConfig(
                subscription_domain=config.subscription_domain,
                pen=None if config.pen == 0 else config.pen,
            ),
            run_groups=list(run_groups.items),
            csip_aus_versions=list(csip_aus_versions.items),
        ).to_dict()
    )


@app.route("/api/config/pen", methods=["POST"])
@api_login_required
def api_config_pen(access_token: str) -> Response | tuple[Response, int]:
    body = request.get_json(silent=True) or {}
    try:
        pen = int(body.get("pen", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "Failed to parse PEN"}), HTTPStatus.BAD_REQUEST
    if not orchestrator.update_config(access_token, pen=pen):
        return jsonify({"error": "Failed to update PEN"}), HTTPStatus.BAD_GATEWAY
    return jsonify({})


@app.route("/api/config/domain", methods=["POST"])
@api_login_required
def api_config_domain(access_token: str) -> Response | tuple[Response, int]:
    body = request.get_json(silent=True) or {}
    domain = body.get("subscription_domain") or ""
    if not orchestrator.update_config(access_token, subscription_domain=domain):
        return jsonify({"error": "Failed to update subscription domain"}), HTTPStatus.BAD_GATEWAY
    return jsonify({})


@app.route("/api/run_groups", methods=["POST"])
@api_login_required
def api_create_run_group(access_token: str) -> Response | tuple[Response, int]:
    body = request.get_json(silent=True) or {}
    version = body.get("csip_aus_version")
    if not version:
        return jsonify({"error": "csip_aus_version is required."}), HTTPStatus.BAD_REQUEST
    result = orchestrator.create_run_group(access_token, version)
    if result is None:
        return jsonify({"error": "Failed to create run group"}), HTTPStatus.BAD_GATEWAY
    return jsonify(result.to_dict()), HTTPStatus.CREATED


@app.route("/api/run_groups/<int:run_group_id>", methods=["PATCH"])
@api_login_required
def api_update_run_group(access_token: str, run_group_id: int) -> Response | tuple[Response, int]:
    body = request.get_json(silent=True) or {}
    name = body.get("name")
    if not name:
        return jsonify({"error": "name is required."}), HTTPStatus.BAD_REQUEST
    result = orchestrator.update_run_group(access_token, run_group_id, name=name)
    if result is None:
        return jsonify({"error": "Failed to update run group"}), HTTPStatus.BAD_GATEWAY
    return jsonify(result.to_dict())


@app.route("/api/run_groups/<int:run_group_id>", methods=["DELETE"])
@api_login_required
def api_delete_run_group(access_token: str, run_group_id: int) -> Response | tuple[Response, int]:
    if not orchestrator.delete_run_group(access_token, run_group_id):
        return jsonify({"error": "Failed to delete run group"}), HTTPStatus.BAD_GATEWAY
    return jsonify({})


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


@app.route("/config/ca_cert", methods=["GET"])
@login_required
def config_ca_cert(access_token: str) -> Response:
    download_bytes = orchestrator.download_certificate_authority_cert(access_token)
    if download_bytes is None:
        return Response(response="Failed to retrieve SERCA.", status=HTTPStatus.BAD_GATEWAY, mimetype="text/plain")
    return send_file(
        io.BytesIO(download_bytes),
        as_attachment=True,
        download_name="cactus-serca.pem",
        mimetype="application/x-x509-ca-cert",
    )


@app.route("/config/run_group/<int:run_group_id>/cert", methods=["GET"])
@login_required
def config_download_run_group_cert(access_token: str, run_group_id: int) -> Response:
    download_bytes, download_file_name = orchestrator.download_client_cert(access_token, run_group_id)
    if download_bytes is None or download_file_name is None:
        return Response(
            response="Failed to retrieve certificate.", status=HTTPStatus.BAD_GATEWAY, mimetype="text/plain"
        )  # noqa: E501
    return send_file(
        io.BytesIO(download_bytes),
        "application/x-x509-user-cert",
        True,
        download_name=download_file_name,
    )


@app.route("/config/run_group/<int:run_group_id>/cert", methods=["POST"])
@login_required
def config_generate_run_group_cert(access_token: str, run_group_id: int) -> Response:
    is_device_cert = request.form.get("type", "device") == "device"
    download_bytes, download_file_name = orchestrator.generate_client_cert(access_token, run_group_id, is_device_cert)
    if download_bytes is None or download_file_name is None:
        return Response(
            response="Failed to generate certificate.", status=HTTPStatus.BAD_GATEWAY, mimetype="text/plain"
        )  # noqa: E501
    return send_file(
        io.BytesIO(download_bytes),
        "application/zip",
        True,
        download_name=download_file_name,
    )


@app.route("/config/shared_cert", methods=["POST"])
@login_required
def config_generate_shared_cert(access_token: str) -> Response:
    download_bytes, download_file_name = orchestrator.generate_shared_client_cert(access_token)
    if download_bytes is None or download_file_name is None:
        return Response(
            response="Failed to generate shared certificate.", status=HTTPStatus.BAD_GATEWAY, mimetype="text/plain"
        )
    return send_file(
        io.BytesIO(download_bytes),
        "application/zip",
        True,
        download_name=download_file_name,
    )


@app.route("/playlist/artifacts", methods=["GET"])
@login_required
def playlist_artifacts_download(access_token: str) -> Response:
    """Browser-native ZIP download for all artifacts in a playlist (plain link; session cookie auth)."""
    run_ids_raw = request.args.get("run_ids", "")
    try:
        run_ids = [int(rid) for rid in run_ids_raw.split(",") if rid]
    except ValueError:
        return Response(response="Invalid run IDs.", status=HTTPStatus.BAD_REQUEST, mimetype="text/plain")

    if not run_ids:
        return Response(response="No run IDs specified.", status=HTTPStatus.BAD_REQUEST, mimetype="text/plain")

    download_name = f"playlist_{run_ids[0]}_artifacts.zip"
    response = download_playlist_artifacts(access_token, run_ids, download_name)
    if response is None:
        return Response(response="Failed to retrieve artifacts.", status=HTTPStatus.BAD_GATEWAY, mimetype="text/plain")
    return response


def _fetch_playlist_runs(
    access_token: str, run_response: schema.RunResponse | None, admin: bool = False
) -> tuple[str | None, list[schema.RunResponse] | None]:
    """Fetch the full RunResponse for every run in this run's playlist.

    This is the one join the orchestrator doesn't do for us: RunResponse.playlist_runs only
    carries summaries (no all_criteria_met / has_artifacts), so the page needs each run's full
    detail. Returns (playlist_name, runs); the frontend derives ordering/active/next from the
    authoritative summary list and looks these up by run_id, so a failed fetch just degrades
    that run's detail rather than breaking the playlist. Returns (None, None) for non-playlist
    runs.
    """
    if run_response is None or not run_response.playlist_runs:
        return None, None

    fetch_run = orchestrator.admin_fetch_individual_run if admin else orchestrator.fetch_individual_run
    playlist_name = session.get("active_playlist", {}).get("name", "Playlist")

    runs: list[schema.RunResponse] = []
    for r in run_response.playlist_runs:
        full_run = fetch_run(access_token, str(r.run_id))
        if full_run is not None:
            runs.append(full_run)

    return playlist_name, runs


@app.route("/run/<int:run_id>/html_report", methods=["GET"])
@login_required
def run_html_report_page(access_token: str, run_id: int) -> str | Response:
    video_start = _parse_video_start(request.args.get("video_start"))
    html, error_detail = orchestrator.fetch_run_power_limit_chart(access_token, run_id, video_start_seconds=video_start)
    if html is None:
        message = error_detail or "Failed to generate HTML report."
        return Response(response=message, status=HTTPStatus.BAD_GATEWAY)
    return Response(html, mimetype="text/html")


# Run status page (React) JSON endpoints. The page shell (metadata + playlist context)
# is one endpoint; the polled RunnerStatus, request details, and proceed are separate.
def _build_run_status_shell(access_token: str, run_id: str, admin: bool) -> RunStatusShell:
    """Assemble the run status page shell: run metadata + playlist context.

    Mirrors the non-status context the old run_status.html template received. The polled
    RunnerStatus is fetched separately by /api/run/<id>/status; there is no base64 blob.
    """
    fetch_status = orchestrator.admin_fetch_run_status if admin else orchestrator.fetch_run_status
    fetch_run = orchestrator.admin_fetch_individual_run if admin else orchestrator.fetch_individual_run

    status = fetch_status(access_token=access_token, run_id=run_id)
    run_response = fetch_run(access_token, run_id)

    run_is_live = status is not None or (run_response is not None and run_response.status in _ACTIVE_RUN_STATUSES)

    playlist_name, playlist_runs = _fetch_playlist_runs(access_token, run_response, admin=admin)

    return RunStatusShell(
        run=run_response,
        run_is_live=run_is_live,
        is_immediate_start=is_immediate_start(run_response),
        playlist_name=playlist_name,
        playlist_runs=playlist_runs,
    )


@app.route("/api/run/<int:run_id>", methods=["GET"])
@api_login_required
def api_run_status(access_token: str, run_id: str) -> Response:
    return jsonify(_build_run_status_shell(access_token, run_id, admin=False).to_dict())


@app.route("/api/admin/run/<int:run_id>", methods=["GET"])
@api_login_required
@api_admin_role_required
def api_admin_run_status(access_token: str, run_id: str) -> Response:
    return jsonify(_build_run_status_shell(access_token, run_id, admin=True).to_dict())


@app.route("/api/run/<int:run_id>/status", methods=["GET"])
@api_login_required
def api_run_status_json(access_token: str, run_id: str) -> Response | tuple[Response, int]:
    status = orchestrator.fetch_run_status(access_token=access_token, run_id=run_id)
    if status is None:
        return jsonify({"error": "Run status unavailable. The test runner has likely terminated."}), HTTPStatus.GONE
    return Response(response=status, status=HTTPStatus.OK, mimetype="application/json")


@app.route("/api/admin/run/<int:run_id>/status", methods=["GET"])
@api_login_required
@api_admin_role_required
def api_admin_run_status_json(access_token: str, run_id: str) -> Response | tuple[Response, int]:
    status = orchestrator.admin_fetch_run_status(access_token=access_token, run_id=run_id)
    if status is None:
        return jsonify({"error": "Run status unavailable. The test runner has likely terminated."}), HTTPStatus.GONE
    return Response(response=status, status=HTTPStatus.OK, mimetype="application/json")


@app.route("/api/run/<int:run_id>/requests/<int:request_id>", methods=["GET"])
@api_login_required
def api_run_request_details(access_token: str, run_id: str, request_id: int) -> Response | tuple[Response, int]:
    """Raw request/response for the request-details modal. Shared by user and admin views."""
    request_data = orchestrator.fetch_request_details(access_token=access_token, request_id=request_id, run_id=run_id)
    if request_data is None:
        return jsonify({"error": "Request details not found"}), HTTPStatus.NOT_FOUND
    return Response(response=request_data, status=HTTPStatus.OK, mimetype="application/json")


@app.route("/api/runs/<int:run_id>/proceed", methods=["POST"])
@api_login_required
def api_send_proceed(access_token: str, run_id: str) -> Response | tuple[Response, int]:
    proceed_response = orchestrator.send_proceed(access_token=access_token, run_id=run_id)
    if proceed_response is None:
        return jsonify({"error": "Failed to proceed to next step"}), HTTPStatus.BAD_GATEWAY
    return Response(response=proceed_response.to_json(), status=HTTPStatus.OK, mimetype="application/json")


@app.route("/api/admin/runs/<int:run_id>/proceed", methods=["POST"])
@api_login_required
@api_admin_role_required
def api_admin_send_proceed(access_token: str, run_id: str) -> Response | tuple[Response, int]:
    proceed_response = orchestrator.admin_send_proceed(access_token=access_token, run_id=run_id)
    if proceed_response is None:
        return jsonify({"error": "Failed to proceed to next step"}), HTTPStatus.BAD_GATEWAY
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


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=int(env.get("PORT", 3000)),
        debug=True,  # noqa: S201  # nosec B201 - not for deployment
    )
