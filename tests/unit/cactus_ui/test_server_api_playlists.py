from datetime import UTC, datetime, timedelta
from http import HTTPStatus

import cactus_schema.orchestrator as schema
import jwt
import pytest
from assertical.fake.generator import generate_class_instance

import cactus_ui.server as server
from cactus_ui.orchestrator import InitialiseRunFailureType, InitRunResult


@pytest.fixture
def client():
    server.app.config.update(TESTING=True)
    with server.app.test_client() as client:
        yield client


def encode_token(permissions: list[str]) -> str:
    return jwt.encode({"permissions": permissions}, "test-signing-key-of-at-least-32-bytes!", algorithm="HS256")


def login(client, permissions: list[str] | None = None) -> None:
    with client.session_transaction() as tx_session:
        tx_session["user"] = {
            "access_token": encode_token(permissions if permissions is not None else ["user:all"]),
            "expires_at": (datetime.now(tz=UTC) + timedelta(hours=1)).timestamp(),
            "userinfo": {"name": "Test User"},
        }


def summary(test_procedure_id: str, category: str, classes: list[str] | None, immediate_start: bool = False):
    return generate_class_instance(
        schema.TestProcedureRunSummaryResponse,
        test_procedure_id=test_procedure_id,
        category=category,
        classes=classes,
        immediate_start=immediate_start,
    )


def single_page(items: list) -> schema.Pagination:
    return schema.Pagination(
        total_pages=1,
        total_items=len(items),
        page_size=100,
        current_page=1,
        prev_page=None,
        next_page=None,
        items=items,
    )


def playlist_run(
    run_id: int,
    test_procedure_id: str,
    status: schema.RunStatusResponse,
    execution_id: str | None,
    order: int | None,
    created_at: datetime,
    all_criteria_met: bool | None = None,
    has_artifacts: bool = False,
) -> schema.RunResponse:
    return generate_class_instance(
        schema.RunResponse,
        run_id=run_id,
        test_procedure_id=test_procedure_id,
        status=status,
        playlist_execution_id=execution_id,
        playlist_order=order,
        created_at=created_at,
        all_criteria_met=all_criteria_met,
        has_artifacts=has_artifacts,
    )


# GET /api/group/<id>/playlist_tests


def test_api_playlist_tests_unauthenticated(client):
    assert client.get("/api/group/1/playlist_tests").status_code == HTTPStatus.UNAUTHORIZED


def test_api_playlist_tests_success(client, monkeypatch):
    login(client)
    procedures = [
        summary("ALL-01", "Generic", ["A", "G"]),
        summary("ALL-02", "Generic", ["A"]),
        summary("IMM-01", "Generic", ["A"], immediate_start=True),
        summary("LOD-01", "Load Control", ["L"]),
    ]
    monkeypatch.setattr(
        server.orchestrator, "fetch_group_procedure_run_summaries", lambda access_token, run_group_id: procedures
    )

    response = client.get("/api/group/1/playlist_tests")

    assert response.status_code == HTTPStatus.OK
    body = response.get_json()
    # immediate_start procedures are excluded; categories preserve definition order
    assert list(body["tests_by_category"].keys()) == ["Generic", "Load Control"]
    assert [t["id"] for t in body["tests_by_category"]["Generic"]] == ["ALL-01", "ALL-02"]
    assert [c["name"] for c in body["classes"]] == ["A", "G", "L"]
    assert all(c["description"] for c in body["classes"])


def test_api_playlist_tests_orchestrator_failure(client, monkeypatch):
    login(client)
    monkeypatch.setattr(
        server.orchestrator, "fetch_group_procedure_run_summaries", lambda access_token, run_group_id: None
    )

    response = client.get("/api/group/1/playlist_tests")

    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert response.get_json() == {"error": "Unable to fetch test procedures."}


# POST /api/group/<id>/playlist


def test_api_init_playlist_requires_procedures(client):
    login(client)

    response = client.post("/api/group/1/playlist", json={})

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.get_json() == {"error": "No tests selected."}


def test_api_init_playlist_success_sets_session(client, monkeypatch):
    login(client)
    init_response = generate_class_instance(
        schema.InitRunResponse,
        run_id=55,
        playlist_execution_id="exec-123",
        playlist_runs=[
            generate_class_instance(schema.PlaylistRunInfo, run_id=55, test_procedure_id="ALL-01"),
            generate_class_instance(schema.PlaylistRunInfo, run_id=56, test_procedure_id="ALL-02"),
        ],
    )
    captured = {}

    def fake_init(access_token, run_group_id, procedures, start_index=0):
        captured["procedures"] = procedures
        return InitRunResult(response=init_response, failure_type=InitialiseRunFailureType.NO_FAILURE)

    monkeypatch.setattr(server.orchestrator, "init_playlist", fake_init)

    response = client.post("/api/group/1/playlist", json={"procedures": ["ALL-01", "ALL-02"]})

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == {"run_id": 55}
    assert captured["procedures"] == ["ALL-01", "ALL-02"]
    with client.session_transaction() as tx_session:
        assert tx_session["active_playlist"]["execution_id"] == "exec-123"
        assert [r["run_id"] for r in tx_session["active_playlist"]["runs"]] == [55, 56]


@pytest.mark.parametrize(
    "failure_type,status,error",
    [
        (
            InitialiseRunFailureType.EXPIRED_CERT,
            HTTPStatus.CONFLICT,
            "Your certificate has expired. Please generate and download a new certificate.",
        ),
        (
            InitialiseRunFailureType.EXISTING_STATIC_INSTANCE,
            HTTPStatus.CONFLICT,
            "You cannot start a second test run while your DeviceCapability URI is set to static.",
        ),
        (
            InitialiseRunFailureType.UNKNOWN_FAILURE,
            HTTPStatus.BAD_GATEWAY,
            "Failed to trigger playlist due to an unknown error.",
        ),
    ],
)
def test_api_init_playlist_failures(client, monkeypatch, failure_type, status, error):
    login(client)
    monkeypatch.setattr(
        server.orchestrator,
        "init_playlist",
        lambda access_token, run_group_id, procedures, start_index=0: InitRunResult(
            response=None, failure_type=failure_type
        ),
    )

    response = client.post("/api/group/1/playlist", json={"procedures": ["ALL-01"]})

    assert response.status_code == status
    assert response.get_json() == {"error": error}


# GET /api/group/<id>/playlist_sessions


def test_api_playlist_sessions_groups_and_sorts(client, monkeypatch):
    login(client)
    older = datetime(2026, 6, 10, tzinfo=UTC)
    newer = datetime(2026, 6, 12, tzinfo=UTC)
    status = schema.RunStatusResponse
    runs = [
        # Past session (older, all finalised) - out of order to exercise sorting
        playlist_run(151, "ALL-02", status.finalised, "past", 1, older, all_criteria_met=False, has_artifacts=True),
        playlist_run(150, "ALL-01", status.finalised, "past", 0, older, all_criteria_met=True, has_artifacts=True),
        # Active session (newer, has a started run)
        playlist_run(200, "ALL-01", status.started, "active", 0, newer),
        playlist_run(201, "ALL-02", status.initialised, "active", 1, newer),
        # A non-playlist run is ignored
        playlist_run(99, "ALL-03", status.finalised, None, None, newer),
    ]
    monkeypatch.setattr(
        server.orchestrator, "fetch_runs_for_group", lambda access_token, run_group_id, p, finalised: single_page(runs)
    )

    response = client.get("/api/group/1/playlist_sessions")

    assert response.status_code == HTTPStatus.OK
    body = response.get_json()
    assert [s["playlist_execution_id"] for s in body] == ["active", "past"]  # active first
    active = body[0]
    assert active["is_active"] is True
    assert active["first_run_id"] == 200
    assert [ts["run_id"] for ts in active["test_statuses"]] == [200, 201]  # sorted by playlist_order
    assert body[1]["is_active"] is False


def test_api_playlist_sessions_empty_on_failure(client, monkeypatch):
    login(client)
    monkeypatch.setattr(server.orchestrator, "fetch_runs_for_group", lambda access_token, run_group_id, p, f: None)

    response = client.get("/api/group/1/playlist_sessions")

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == []


# POST /api/runs/<id>/finalise_playlist


def test_api_finalise_playlist(client, monkeypatch):
    login(client)
    calls = {}
    monkeypatch.setattr(
        server.orchestrator, "finalise_playlist", lambda access_token, run_id: calls.setdefault("run_id", run_id)
    )

    response = client.post("/api/runs/55/finalise_playlist")

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == {"run_id": 55}
    assert calls["run_id"] == "55"


# GET /playlist/artifacts (browser-native download)


def test_playlist_artifacts_redirects_to_login_when_logged_out(client):
    response = client.get("/playlist/artifacts?run_ids=1,2")

    assert response.status_code == HTTPStatus.FOUND
    assert "/login" in response.headers["Location"]


def test_playlist_artifacts_success(client, monkeypatch):
    login(client)
    captured = {}

    def fake_fetch(access_token, run_ids):
        captured["run_ids"] = run_ids
        return b"zipbytes"

    monkeypatch.setattr(server.orchestrator, "fetch_multiple_run_artifacts", fake_fetch)

    response = client.get("/playlist/artifacts?run_ids=150,151")

    assert response.status_code == HTTPStatus.OK
    assert response.data == b"zipbytes"
    assert response.mimetype == "application/zip"
    assert "playlist_150_artifacts.zip" in response.headers["Content-Disposition"]
    assert captured["run_ids"] == [150, 151]


def test_playlist_artifacts_requires_run_ids(client):
    login(client)

    response = client.get("/playlist/artifacts")

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert b"No run IDs specified." in response.data


def test_playlist_artifacts_failure(client, monkeypatch):
    login(client)
    monkeypatch.setattr(server.orchestrator, "fetch_multiple_run_artifacts", lambda access_token, run_ids: None)

    response = client.get("/playlist/artifacts?run_ids=150")

    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert b"Failed to retrieve artifacts." in response.data
