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


# /api/config GET


def test_api_config_unauthenticated(client):
    assert client.get("/api/config").status_code == HTTPStatus.UNAUTHORIZED


def test_api_config_success(client, monkeypatch):
    login(client)
    config = schema.UserConfigurationResponse(
        subscription_domain="my.example.com",
        is_static_uri=False,
        pen=123456,
        static_uri=None,
    )
    rg = generate_class_instance(schema.RunGroupResponse, seed=0)
    run_groups = schema.Pagination(
        total_pages=1, total_items=1, page_size=10, current_page=1, prev_page=None, next_page=None, items=[rg]
    )
    version = generate_class_instance(schema.CSIPAusVersionResponse, seed=0)
    versions = schema.Pagination(
        total_pages=1, total_items=1, page_size=10, current_page=1, prev_page=None, next_page=None, items=[version]
    )

    monkeypatch.setattr(server.orchestrator, "fetch_config", lambda at: config)
    monkeypatch.setattr(server.orchestrator, "fetch_run_groups", lambda at, p: run_groups)
    monkeypatch.setattr(server.orchestrator, "fetch_csip_aus_versions", lambda at, p: versions)

    response = client.get("/api/config")

    assert response.status_code == HTTPStatus.OK
    body = response.get_json()
    assert body["config"]["subscription_domain"] == "my.example.com"
    assert body["config"]["is_static_uri"] is False
    assert body["config"]["pen"] == 123456
    assert body["config"]["static_uri"] is None
    assert len(body["run_groups"]) == 1
    assert len(body["csip_aus_versions"]) == 1


def test_api_config_pen_zero_returns_null(client, monkeypatch):
    login(client)
    config = schema.UserConfigurationResponse(
        subscription_domain="",
        is_static_uri=False,
        pen=0,
        static_uri=None,
    )
    run_groups = schema.Pagination(
        total_pages=1, total_items=0, page_size=10, current_page=1, prev_page=None, next_page=None, items=[]
    )
    versions = schema.Pagination(
        total_pages=1, total_items=0, page_size=10, current_page=1, prev_page=None, next_page=None, items=[]
    )
    monkeypatch.setattr(server.orchestrator, "fetch_config", lambda at: config)
    monkeypatch.setattr(server.orchestrator, "fetch_run_groups", lambda at, p: run_groups)
    monkeypatch.setattr(server.orchestrator, "fetch_csip_aus_versions", lambda at, p: versions)

    response = client.get("/api/config")

    assert response.status_code == HTTPStatus.OK
    assert response.get_json()["config"]["pen"] is None


def test_api_config_orchestrator_failure(client, monkeypatch):
    login(client)
    monkeypatch.setattr(server.orchestrator, "fetch_config", lambda at: None)
    monkeypatch.setattr(server.orchestrator, "fetch_run_groups", lambda at, p: None)
    monkeypatch.setattr(server.orchestrator, "fetch_csip_aus_versions", lambda at, p: None)

    response = client.get("/api/config")

    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert "error" in response.get_json()


# /api/config/pen


def test_api_config_pen_success(client, monkeypatch):
    login(client)
    calls = {}
    monkeypatch.setattr(server.orchestrator, "update_config", lambda at, **kw: calls.update(kw) or True)

    response = client.post("/api/config/pen", json={"pen": 99999})

    assert response.status_code == HTTPStatus.OK
    assert calls.get("pen") == 99999


def test_api_config_pen_bad_value(client):
    login(client)

    response = client.post("/api/config/pen", json={"pen": "not-a-number"})

    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_api_config_pen_orchestrator_failure(client, monkeypatch):
    login(client)
    monkeypatch.setattr(server.orchestrator, "update_config", lambda at, **kw: False)

    response = client.post("/api/config/pen", json={"pen": 1})

    assert response.status_code == HTTPStatus.BAD_GATEWAY


# /api/config/domain


def test_api_config_domain_success(client, monkeypatch):
    login(client)
    calls = {}
    monkeypatch.setattr(server.orchestrator, "update_config", lambda at, **kw: calls.update(kw) or True)

    response = client.post("/api/config/domain", json={"subscription_domain": "test.example.com"})

    assert response.status_code == HTTPStatus.OK
    assert calls.get("subscription_domain") == "test.example.com"


def test_api_config_domain_empty_clears(client, monkeypatch):
    login(client)
    calls = {}
    monkeypatch.setattr(server.orchestrator, "update_config", lambda at, **kw: calls.update(kw) or True)

    response = client.post("/api/config/domain", json={})

    assert response.status_code == HTTPStatus.OK
    assert calls.get("subscription_domain") == ""


# /api/config/static_uri


def test_api_config_static_uri_success(client, monkeypatch):
    login(client)
    calls = {}
    monkeypatch.setattr(server.orchestrator, "update_config", lambda at, **kw: calls.update(kw) or True)

    response = client.post("/api/config/static_uri", json={"is_static_uri": True})

    assert response.status_code == HTTPStatus.OK
    assert calls.get("is_static_uri") is True


# /api/run_groups POST (create)


def test_api_create_run_group_success(client, monkeypatch):
    login(client)
    rg = generate_class_instance(schema.RunGroupResponse, seed=0)
    monkeypatch.setattr(server.orchestrator, "create_run_group", lambda at, ver: rg)

    response = client.post("/api/run_groups", json={"csip_aus_version": "v1.2"})

    assert response.status_code == HTTPStatus.CREATED
    assert response.get_json()["run_group_id"] == rg.run_group_id


def test_api_create_run_group_missing_version(client):
    login(client)

    response = client.post("/api/run_groups", json={})

    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_api_create_run_group_orchestrator_failure(client, monkeypatch):
    login(client)
    monkeypatch.setattr(server.orchestrator, "create_run_group", lambda at, ver: None)

    response = client.post("/api/run_groups", json={"csip_aus_version": "v1.2"})

    assert response.status_code == HTTPStatus.BAD_GATEWAY


# /api/run_groups/<id> PATCH (update)


def test_api_update_run_group_success(client, monkeypatch):
    login(client)
    rg = generate_class_instance(schema.RunGroupResponse, seed=1)
    calls = {}
    monkeypatch.setattr(
        server.orchestrator, "update_run_group", lambda at, rid, name: calls.update({"rid": rid, "name": name}) or rg
    )

    response = client.patch("/api/run_groups/5", json={"name": "New Name"})

    assert response.status_code == HTTPStatus.OK
    assert calls["rid"] == 5
    assert calls["name"] == "New Name"


def test_api_update_run_group_missing_name(client):
    login(client)

    response = client.patch("/api/run_groups/1", json={})

    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_api_update_run_group_orchestrator_failure(client, monkeypatch):
    login(client)
    monkeypatch.setattr(server.orchestrator, "update_run_group", lambda at, rid, name: None)

    response = client.patch("/api/run_groups/1", json={"name": "x"})

    assert response.status_code == HTTPStatus.BAD_GATEWAY


# /api/run_groups/<id> DELETE


def test_api_delete_run_group_success(client, monkeypatch):
    login(client)
    calls = {}
    monkeypatch.setattr(server.orchestrator, "delete_run_group", lambda at, rid: calls.update({"rid": rid}) or True)

    response = client.delete("/api/run_groups/7")

    assert response.status_code == HTTPStatus.OK
    assert calls["rid"] == 7


def test_api_delete_run_group_orchestrator_failure(client, monkeypatch):
    login(client)
    monkeypatch.setattr(server.orchestrator, "delete_run_group", lambda at, rid: False)

    response = client.delete("/api/run_groups/1")

    assert response.status_code == HTTPStatus.BAD_GATEWAY
