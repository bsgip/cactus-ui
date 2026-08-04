from datetime import UTC, datetime, timedelta
from http import HTTPStatus

import jwt
import pytest
from cactus_schema.orchestrator import DeployReleaseResponse

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


def test_api_release_notes_unauthenticated(client):
    assert client.get("/api/release-notes").status_code == HTTPStatus.UNAUTHORIZED


def test_api_release_notes_success(client, monkeypatch, release_asset):
    login(client)
    deploy = DeployReleaseResponse(release_tag="177", created_at=datetime(2026, 7, 26, 4, 30, tzinfo=UTC))
    monkeypatch.setattr(server.release_notes, "fetch_releases", lambda: [release_asset])
    monkeypatch.setattr(server.orchestrator, "fetch_deploy_releases", lambda at: [deploy])

    response = client.get("/api/release-notes")

    assert response.status_code == HTTPStatus.OK
    body = response.get_json()
    assert [r["tag"] for r in body["releases"]] == ["release-177"]
    assert body["releases"][0]["deployed_at"] == body["deploy_history"][0]["created_at"]
    assert [d["release_tag"] for d in body["deploy_history"]] == ["177"]


def test_api_release_notes_without_github(client, monkeypatch):
    """GitHub being unreachable is an empty page with a link-out, not an error."""
    login(client)
    monkeypatch.setattr(server.release_notes, "fetch_releases", lambda: [])
    monkeypatch.setattr(server.orchestrator, "fetch_deploy_releases", lambda at: [])

    response = client.get("/api/release-notes")

    assert response.status_code == HTTPStatus.OK
    assert response.get_json()["releases"] == []


def test_api_release_notes_without_deploy_history(client, monkeypatch, release_asset):
    """An orchestrator failure costs the deploy timestamps and nothing else."""
    login(client)
    monkeypatch.setattr(server.release_notes, "fetch_releases", lambda: [release_asset])
    monkeypatch.setattr(server.orchestrator, "fetch_deploy_releases", lambda at: None)

    response = client.get("/api/release-notes")

    assert response.status_code == HTTPStatus.OK
    body = response.get_json()
    assert body["releases"][0]["deployed_at"] is None
    assert body["deploy_history"] == []
