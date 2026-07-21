from datetime import UTC, datetime, timedelta
from http import HTTPStatus

import cactus_schema.orchestrator as schema
import jwt
import pytest
from assertical.fake.generator import generate_class_instance

import cactus_ui.server as server


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


def make_run(**overrides) -> schema.RunResponse:
    # playlist_runs=None keeps _fetch_playlist_runs on its trivial (None, None) path.
    return generate_class_instance(schema.RunResponse, playlist_runs=None, **overrides)


# GET /api/run/<id>  (page shell)


def test_api_run_status_unauthenticated(client):
    assert client.get("/api/run/1").status_code == HTTPStatus.UNAUTHORIZED


def test_api_run_status_live_run(client, monkeypatch):
    login(client)
    run = make_run(status=schema.RunStatusResponse.started, test_procedure_id="ALL-08", immediate_start=False)
    monkeypatch.setattr(server.orchestrator, "fetch_run_status", lambda access_token, run_id: '{"status_summary": "x"}')
    monkeypatch.setattr(server.orchestrator, "fetch_individual_run", lambda access_token, run_id: run)

    response = client.get("/api/run/1")

    assert response.status_code == HTTPStatus.OK
    body = response.get_json()
    assert body["run_is_live"] is True
    # The run is forwarded as the canonical RunResponse (no reshaping/renaming).
    assert body["run"]["run_id"] == run.run_id
    assert body["run"]["status"] == "started"
    assert body["run"]["test_url"] == run.test_url
    assert body["run"]["test_procedure_id"] == run.test_procedure_id
    assert body["run"]["immediate_start"] is False
    assert body["playlist_name"] is None
    assert body["playlist_runs"] is None


def test_api_run_status_immediate_start_procedure(client, monkeypatch):
    login(client)
    run = make_run(status=schema.RunStatusResponse.finalised, test_procedure_id="ALL-01", immediate_start=True)
    monkeypatch.setattr(server.orchestrator, "fetch_run_status", lambda access_token, run_id: None)
    monkeypatch.setattr(server.orchestrator, "fetch_individual_run", lambda access_token, run_id: run)

    assert client.get("/api/run/1").get_json()["run"]["immediate_start"] is True


def test_api_run_status_not_found(client, monkeypatch):
    login(client)
    monkeypatch.setattr(server.orchestrator, "fetch_run_status", lambda access_token, run_id: None)
    monkeypatch.setattr(server.orchestrator, "fetch_individual_run", lambda access_token, run_id: None)

    response = client.get("/api/run/7")

    assert response.status_code == HTTPStatus.OK
    body = response.get_json()
    assert body["run_is_live"] is False
    assert body["run"] is None


def test_api_run_status_finalised_not_live(client, monkeypatch):
    login(client)
    run = make_run(status=schema.RunStatusResponse.finalised, has_artifacts=True, classes=[])
    monkeypatch.setattr(server.orchestrator, "fetch_run_status", lambda access_token, run_id: None)
    monkeypatch.setattr(server.orchestrator, "fetch_individual_run", lambda access_token, run_id: run)

    body = client.get("/api/run/3").get_json()

    assert body["run_is_live"] is False
    assert body["run"]["status"] == "finalised"
    assert body["run"]["has_artifacts"] is True


def test_api_run_status_playlist_join(client, monkeypatch):
    # The shell joins each playlist run's full RunResponse (the orchestrator only gives
    # summaries); the frontend derives ordering/active/next from these.
    login(client)
    summary = [
        generate_class_instance(schema.PlaylistRunInfo, run_id=201),
        generate_class_instance(schema.PlaylistRunInfo, run_id=202),
    ]
    main_run = make_run(status=schema.RunStatusResponse.started, playlist_order=0)
    main_run.playlist_runs = summary
    runs = {
        "3": main_run,
        "201": make_run(run_id=201, status=schema.RunStatusResponse.finalised, has_artifacts=True),
        "202": make_run(run_id=202, status=schema.RunStatusResponse.started),
    }
    monkeypatch.setattr(server.orchestrator, "fetch_run_status", lambda access_token, run_id: None)
    monkeypatch.setattr(server.orchestrator, "fetch_individual_run", lambda access_token, run_id: runs.get(str(run_id)))
    with client.session_transaction() as tx:
        tx["active_playlist"] = {"name": "My Playlist"}

    body = client.get("/api/run/3").get_json()

    assert body["playlist_name"] == "My Playlist"
    # Forwarded as full RunResponses, in playlist order.
    assert [r["run_id"] for r in body["playlist_runs"]] == [201, 202]
    assert body["playlist_runs"][0]["has_artifacts"] is True


def test_api_admin_run_status_forbidden_for_non_admin(client):
    login(client, ["user:all"])
    assert client.get("/api/admin/run/1").status_code == HTTPStatus.FORBIDDEN


def test_api_admin_run_status_uses_admin_orchestrator(client, monkeypatch):
    login(client, ["user:all", "admin:all"])
    run = make_run(status=schema.RunStatusResponse.started, classes=[])
    calls = {}

    def admin_status(access_token, run_id):
        calls["status"] = run_id
        return '{"status_summary": "x"}'

    def admin_run(access_token, run_id):
        calls["run"] = run_id
        return run

    monkeypatch.setattr(server.orchestrator, "admin_fetch_run_status", admin_status)
    monkeypatch.setattr(server.orchestrator, "admin_fetch_individual_run", admin_run)

    response = client.get("/api/admin/run/9")

    assert response.status_code == HTTPStatus.OK
    assert response.get_json()["run_is_live"] is True
    assert calls == {"status": 9, "run": 9}


# GET /api/run/<id>/status  (polled RunnerStatus)


def test_api_run_status_json_success(client, monkeypatch):
    login(client)
    monkeypatch.setattr(
        server.orchestrator, "fetch_run_status", lambda access_token, run_id: '{"status_summary": "ok"}'
    )

    response = client.get("/api/run/1/status")

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == {"status_summary": "ok"}


def test_api_run_status_json_gone(client, monkeypatch):
    login(client)
    monkeypatch.setattr(server.orchestrator, "fetch_run_status", lambda access_token, run_id: None)

    response = client.get("/api/run/1/status")

    assert response.status_code == HTTPStatus.GONE
    assert response.get_json()["error"]


def test_api_admin_run_status_json_forbidden(client):
    login(client, ["user:all"])
    assert client.get("/api/admin/run/1/status").status_code == HTTPStatus.FORBIDDEN


def test_api_admin_run_status_json_success(client, monkeypatch):
    login(client, ["user:all", "admin:all"])
    monkeypatch.setattr(
        server.orchestrator, "admin_fetch_run_status", lambda access_token, run_id: '{"status_summary": "ok"}'
    )

    assert client.get("/api/admin/run/1/status").get_json() == {"status_summary": "ok"}


# GET /api/run/<id>/requests/<request_id>


def test_api_run_request_details_success(client, monkeypatch):
    login(client)
    monkeypatch.setattr(
        server.orchestrator,
        "fetch_request_details",
        lambda access_token, request_id, run_id: '{"request": "GET /edev", "response": "200"}',
    )

    response = client.get("/api/run/1/requests/5")

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == {"request": "GET /edev", "response": "200"}


def test_api_run_request_details_not_found(client, monkeypatch):
    login(client)
    monkeypatch.setattr(server.orchestrator, "fetch_request_details", lambda access_token, request_id, run_id: None)

    response = client.get("/api/run/1/requests/5")

    assert response.status_code == HTTPStatus.NOT_FOUND
    assert response.get_json() == {"error": "Request details not found"}


# POST /api/runs/<id>/proceed


def test_api_send_proceed_success(client, monkeypatch):
    login(client)
    proceed = generate_class_instance(schema.ProceedResponse, handled=True)
    monkeypatch.setattr(server.orchestrator, "send_proceed", lambda access_token, run_id: proceed)

    response = client.post("/api/runs/1/proceed")

    assert response.status_code == HTTPStatus.OK
    assert response.get_json()["handled"] is True


def test_api_send_proceed_failure(client, monkeypatch):
    login(client)
    monkeypatch.setattr(server.orchestrator, "send_proceed", lambda access_token, run_id: None)

    response = client.post("/api/runs/1/proceed")

    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert response.get_json() == {"error": "Failed to proceed to next step"}


def test_api_admin_send_proceed_forbidden(client):
    login(client, ["user:all"])
    assert client.post("/api/admin/runs/1/proceed").status_code == HTTPStatus.FORBIDDEN


def test_api_admin_send_proceed_success(client, monkeypatch):
    login(client, ["user:all", "admin:all"])
    proceed = generate_class_instance(schema.ProceedResponse, handled=False)
    monkeypatch.setattr(server.orchestrator, "admin_send_proceed", lambda access_token, run_id: proceed)

    response = client.post("/api/admin/runs/1/proceed")

    assert response.status_code == HTTPStatus.OK
    assert response.get_json()["handled"] is False
