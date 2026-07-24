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


def make_summary(
    test_procedure_id: str,
    classes: list[str] | None,
    run_count: int = 0,
    latest_run_status: int | None = None,
    latest_all_criteria_met: bool | None = None,
    latest_run_id: int | None = None,
) -> schema.TestProcedureRunSummaryResponse:
    return generate_class_instance(
        schema.TestProcedureRunSummaryResponse,
        test_procedure_id=test_procedure_id,
        classes=classes,
        run_count=run_count,
        latest_run_status=latest_run_status,
        latest_all_criteria_met=latest_all_criteria_met,
        latest_run_id=latest_run_id,
    )


# /api/group/<id>/compliance


def test_api_group_compliance_unauthenticated(client):
    assert client.get("/api/group/1/compliance").status_code == HTTPStatus.UNAUTHORIZED


def test_api_group_compliance_fetch_error(client, monkeypatch):
    login(client)
    monkeypatch.setattr(server.orchestrator, "fetch_group_procedure_run_summaries", lambda *a, **kw: None)

    response = client.get("/api/group/1/compliance")

    assert response.status_code == HTTPStatus.BAD_GATEWAY


def test_api_group_compliance_success(client, monkeypatch):
    login(client)
    all01 = make_summary(
        "ALL-01", ["A"], run_count=1, latest_run_status=3, latest_all_criteria_met=True, latest_run_id=100
    )
    procedures = [
        all01,
        make_summary("ALL-02", ["A"], run_count=0),
        make_summary("ALL-03", ["C"], run_count=1, latest_run_status=2, latest_run_id=101),
    ]
    monkeypatch.setattr(server.orchestrator, "fetch_group_procedure_run_summaries", lambda *a, **kw: procedures)

    response = client.get("/api/group/1/compliance")

    assert response.status_code == HTTPStatus.OK
    data = response.get_json()
    assert "compliance_by_class" in data

    by_class = {e["class_name"]: e for e in data["compliance_by_class"]}

    # Class A: ALL-01 success, ALL-02 runless -> not fully compliant
    assert "A" in by_class
    assert by_class["A"]["compliant"] is False
    statuses_a = {r["test_procedure_id"]: r["status"] for r in by_class["A"]["per_run_status"]}
    assert statuses_a["ALL-01"] == "success"
    assert statuses_a["ALL-02"] == "runless"

    # Class C: ALL-03 active -> not compliant
    assert "C" in by_class
    assert by_class["C"]["compliant"] is False
    assert by_class["C"]["per_run_status"][0]["status"] == "active"
    assert by_class["C"]["per_run_status"][0]["latest_run_id"] == 101

    # class_details shape
    assert by_class["A"]["class_details"]["name"] == "A"
    assert isinstance(by_class["A"]["class_details"]["description"], str)


def test_api_group_compliance_all_success(client, monkeypatch):
    login(client)
    all01 = make_summary(
        "ALL-01", ["A"], run_count=1, latest_run_status=3, latest_all_criteria_met=True, latest_run_id=100
    )
    procedures = [all01]
    monkeypatch.setattr(server.orchestrator, "fetch_group_procedure_run_summaries", lambda *a, **kw: procedures)

    response = client.get("/api/group/1/compliance")

    data = response.get_json()
    by_class = {e["class_name"]: e for e in data["compliance_by_class"]}
    assert by_class["A"]["compliant"] is True


# /api/admin/group/<id>/compliance


def test_api_admin_group_compliance_unauthenticated(client):
    assert client.get("/api/admin/group/1/compliance").status_code == HTTPStatus.UNAUTHORIZED


def test_api_admin_group_compliance_forbidden(client):
    login(client, ["user:all"])
    assert client.get("/api/admin/group/1/compliance").status_code == HTTPStatus.FORBIDDEN


def test_api_admin_group_compliance_success(client, monkeypatch):
    login(client, ["user:all", "admin:all"])
    all01 = make_summary(
        "ALL-01", ["A"], run_count=2, latest_run_status=3, latest_all_criteria_met=False, latest_run_id=99
    )
    procedures = [all01]
    monkeypatch.setattr(
        server.orchestrator,
        "admin_fetch_group_procedure_run_summaries",
        lambda *a, **kw: procedures,
    )

    response = client.get("/api/admin/group/1/compliance")

    assert response.status_code == HTTPStatus.OK
    data = response.get_json()
    by_class = {e["class_name"]: e for e in data["compliance_by_class"]}
    assert by_class["A"]["per_run_status"][0]["status"] == "failed"


# /admin/group/<id>/compliance_pdf


def test_admin_compliance_pdf_redirects_when_logged_out(client):
    assert client.get("/admin/group/1/compliance_pdf").status_code == HTTPStatus.FOUND


def test_admin_compliance_pdf_redirects_non_admin(client):
    login(client, ["user:all"])
    assert client.get("/admin/group/1/compliance_pdf").status_code == HTTPStatus.FOUND


def test_admin_compliance_pdf_fetch_error(client, monkeypatch):
    login(client, ["user:all", "admin:all"])
    monkeypatch.setattr(server.orchestrator, "admin_fetch_run_group_artifact", lambda *a, **kw: None)

    response = client.get("/admin/group/1/compliance_pdf")

    assert response.status_code == HTTPStatus.BAD_GATEWAY


def test_admin_compliance_pdf_success(client, monkeypatch):
    login(client, ["user:all", "admin:all"])
    pdf_bytes = b"%PDF-1.4 fake pdf content"
    monkeypatch.setattr(server.orchestrator, "admin_fetch_run_group_artifact", lambda *a, **kw: pdf_bytes)

    response = client.get("/admin/group/1/compliance_pdf")

    assert response.status_code == HTTPStatus.OK
    assert response.content_type == "application/pdf"
    assert response.data == pdf_bytes
    assert "1_compliance.pdf" in response.headers.get("Content-Disposition", "")
