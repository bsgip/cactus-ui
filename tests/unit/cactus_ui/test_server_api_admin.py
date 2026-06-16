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
            "access_token": encode_token(permissions if permissions is not None else ["user:all", "admin:all"]),
            "expires_at": (datetime.now(tz=UTC) + timedelta(hours=1)).timestamp(),
            "userinfo": {"name": "Admin User"},
        }


# /api/admin/users


def test_api_admin_users_unauthenticated(client):
    assert client.get("/api/admin/users").status_code == HTTPStatus.UNAUTHORIZED


def test_api_admin_users_forbidden(client):
    login(client, permissions=["user:all"])

    assert client.get("/api/admin/users").status_code == HTTPStatus.FORBIDDEN


def test_api_admin_users_fetch_error(client, monkeypatch):
    login(client)
    monkeypatch.setattr(server.orchestrator, "admin_fetch_users", lambda *a, **kw: None)

    response = client.get("/api/admin/users")

    assert response.status_code == HTTPStatus.BAD_GATEWAY


def test_api_admin_users_success(client, monkeypatch):
    login(client)
    run_group = generate_class_instance(schema.RunGroupResponse, run_group_id=10, name="Battery Mk1")
    user_with_groups = generate_class_instance(
        schema.UserWithRunGroupsResponse, user_id=1, name="Alice", run_groups=[run_group]
    )
    user_no_groups = generate_class_instance(
        schema.UserWithRunGroupsResponse, user_id=2, name=None, run_groups=[]
    )
    monkeypatch.setattr(
        server.orchestrator, "admin_fetch_users", lambda *a, **kw: [user_with_groups, user_no_groups]
    )

    response = client.get("/api/admin/users")

    assert response.status_code == HTTPStatus.OK
    data = response.get_json()
    assert "users" in data
    assert len(data["users"]) == 2

    u1 = data["users"][0]
    assert u1["user_id"] == 1
    assert u1["name"] == "Alice"
    assert len(u1["run_groups"]) == 1
    assert u1["run_groups"][0]["run_group_id"] == 10
    assert u1["run_groups"][0]["name"] == "Battery Mk1"
    assert "matchable_description" in u1
    assert "1" in u1["matchable_description"]
    assert "Alice" in u1["matchable_description"]
    assert "10" in u1["matchable_description"]
    assert "Battery Mk1" in u1["matchable_description"]

    u2 = data["users"][1]
    assert u2["user_id"] == 2
    assert u2["name"] is None
    assert u2["run_groups"] == []
    assert u2["matchable_description"] == "2"
