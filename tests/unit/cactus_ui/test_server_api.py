from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from typing import Any, cast

import cactus_schema.orchestrator as schema
import jwt
import pytest
from assertical.fake.generator import generate_class_instance
from flask import session as flask_session

import cactus_ui.server as server


def as_loose_callable(decorated_endpoint) -> Callable[..., Any]:
    """The api decorators claim to preserve the wrapped signature; tests exercise the actual
    wrapper behaviour (no-arg calls, error tuple returns), so loosen the type."""
    return cast(Callable[..., Any], decorated_endpoint)


@pytest.fixture
def client():
    server.app.config.update(TESTING=True)
    with server.app.test_client() as client:
        yield client


def encode_token(permissions: list[str]) -> str:
    return jwt.encode({"permissions": permissions}, "test-signing-key-of-at-least-32-bytes!", algorithm="HS256")


def session_user(permissions: list[str], expires_in: timedelta = timedelta(hours=1)) -> dict:
    return {
        "access_token": encode_token(permissions),
        "expires_at": (datetime.now(tz=UTC) + expires_in).timestamp(),
        "userinfo": {"name": "Test User"},
    }


def login(client, permissions: list[str] | None = None) -> None:
    with client.session_transaction() as tx_session:
        tx_session["user"] = session_user(permissions if permissions is not None else ["user:all"])


def test_api_session_unauthenticated(client):
    response = client.get("/api/session")

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    body = response.get_json()
    assert body["error"] == "unauthenticated"
    assert "login_banner_message" in body


def test_api_session_expired_token(client):
    with client.session_transaction() as tx_session:
        tx_session["user"] = session_user(["user:all"], expires_in=timedelta(hours=-1))

    response = client.get("/api/session")

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.get_json()["error"] == "unauthenticated"


def test_api_session_logged_in(client):
    login(client, ["user:all"])

    response = client.get("/api/session")

    assert response.status_code == HTTPStatus.OK
    body = response.get_json()
    assert body["username"] == "Test User"
    assert body["permissions"] == ["user:all"]
    assert body["version"] == server.CACTUS_PLATFORM_VERSION
    assert body["support_email"] == server.CACTUS_PLATFORM_SUPPORT_EMAIL
    assert "banner_message" in body
    assert isinstance(body["hosted_images"], list)


def test_api_login_required_rejects_missing_session():
    @as_loose_callable
    @server.api_login_required
    def endpoint(access_token: str) -> str:
        return "ok"

    with server.app.test_request_context("/api/anything"):
        response, status = endpoint()

    assert status == HTTPStatus.UNAUTHORIZED
    assert response.get_json() == {"error": "unauthenticated"}


def test_api_login_required_passes_access_token():
    @as_loose_callable
    @server.api_login_required
    def endpoint(access_token: str) -> str:
        return access_token

    with server.app.test_request_context("/api/anything"):
        user = session_user(["user:all"])
        flask_session["user"] = user
        assert endpoint() == user["access_token"]


def test_api_admin_role_required_rejects_non_admin():
    @as_loose_callable
    @server.api_admin_role_required
    def endpoint() -> str:
        return "ok"

    with server.app.test_request_context("/api/admin/anything"):
        flask_session["user"] = session_user(["user:all"])
        response, status = endpoint()

    assert status == HTTPStatus.FORBIDDEN
    assert response.get_json() == {"error": "forbidden"}


def test_api_admin_role_required_passes_admin():
    @server.api_admin_role_required
    def endpoint() -> str:
        return "ok"

    with server.app.test_request_context("/api/admin/anything"):
        flask_session["user"] = session_user(["user:all", "admin:all"])
        assert endpoint() == "ok"


def procedure_page(items: list[schema.TestProcedureResponse], page: int, next_page: int | None):
    return schema.Pagination(
        total_pages=2 if next_page else 1,
        total_items=len(items),
        page_size=len(items),
        current_page=page,
        prev_page=None if page == 1 else page - 1,
        next_page=next_page,
        items=items,
    )


def test_api_procedures_unauthenticated(client):
    response = client.get("/api/procedures")

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.get_json() == {"error": "unauthenticated"}


def test_api_procedures_flattens_pagination(client, monkeypatch):
    login(client)
    procedures = [generate_class_instance(schema.TestProcedureResponse, seed=i) for i in range(3)]
    pages = {1: procedure_page(procedures[:2], 1, 2), 2: procedure_page(procedures[2:], 2, None)}
    monkeypatch.setattr(server.orchestrator, "fetch_procedures", lambda access_token, page: pages[page])

    response = client.get("/api/procedures")

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == {"procedures": [p.to_dict() for p in procedures]}


def test_api_procedures_orchestrator_failure(client, monkeypatch):
    login(client)
    monkeypatch.setattr(server.orchestrator, "fetch_procedures", lambda access_token, page: None)

    response = client.get("/api/procedures")

    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert response.get_json() == {"error": "Failed to retrieve procedures."}


def test_api_procedure_yaml_unauthenticated(client):
    response = client.get("/api/procedure/ALL-01")

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.get_json() == {"error": "unauthenticated"}


def test_api_procedure_yaml_success(client, monkeypatch):
    login(client)
    monkeypatch.setattr(
        server.orchestrator, "fetch_procedure_yaml", lambda access_token, test_procedure_id: "Description: A test\n"
    )

    response = client.get("/api/procedure/ALL-01")

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == {"test_procedure_id": "ALL-01", "yaml": "Description: A test\n"}


def test_api_procedure_yaml_orchestrator_failure(client, monkeypatch):
    login(client)
    monkeypatch.setattr(server.orchestrator, "fetch_procedure_yaml", lambda access_token, test_procedure_id: None)

    response = client.get("/api/procedure/ALL-01")

    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert response.get_json() == {"error": "Failed to fetch YAML for test 'ALL-01'."}


@pytest.fixture
def spa_dist(monkeypatch, tmp_path):
    (tmp_path / "index.html").write_text("<html><body>SPA index</body></html>")
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "app.js").write_text("console.log('spa');")
    monkeypatch.setattr(server, "FRONTEND_DIST_DIR", tmp_path)
    return tmp_path


def test_root_serves_spa_index(client, spa_dist):
    response = client.get("/")

    assert response.status_code == HTTPStatus.OK
    assert b"SPA index" in response.data


def test_catch_all_serves_index_for_client_routes(client, spa_dist):
    response = client.get("/group/1/runs-client-route")

    assert response.status_code == HTTPStatus.OK
    assert b"SPA index" in response.data


def test_catch_all_serves_real_asset_files(client, spa_dist):
    response = client.get("/assets/app.js")

    assert response.status_code == HTTPStatus.OK
    assert b"console.log('spa');" in response.data


def test_catch_all_unknown_api_path_is_404_json(client, spa_dist):
    response = client.get("/api/does/not/exist")

    assert response.status_code == HTTPStatus.NOT_FOUND
    assert response.get_json() == {"error": "not found"}
