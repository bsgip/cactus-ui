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


def _paginate(items: list) -> schema.Pagination:
    return schema.Pagination(
        total_pages=1,
        total_items=len(items),
        page_size=10,
        current_page=1,
        prev_page=None,
        next_page=None,
        items=items,
    )


# GET /api/compliance/requests (user list)


def test_api_compliance_requests_unauthenticated(client):
    assert client.get("/api/compliance/requests").status_code == HTTPStatus.UNAUTHORIZED


def test_api_compliance_requests_fetch_error(client, monkeypatch):
    login(client)
    monkeypatch.setattr(server.orchestrator, "fetch_compliance_requests", lambda *a, **kw: None)
    assert client.get("/api/compliance/requests").status_code == HTTPStatus.BAD_GATEWAY


def test_api_compliance_requests_success(client, monkeypatch):
    login(client)
    req = generate_class_instance(schema.ComplianceRequestResponse, seed=1)
    monkeypatch.setattr(server.orchestrator, "fetch_compliance_requests", lambda at, page: _paginate([req]))

    response = client.get("/api/compliance/requests")

    assert response.status_code == HTTPStatus.OK
    body = response.get_json()
    assert len(body["requests"]) == 1
    assert body["requests"][0]["compliance_request_id"] == req.compliance_request_id


# GET /api/admin/compliance/requests (admin list)


def test_api_admin_compliance_requests_forbidden(client):
    login(client, ["user:all"])
    assert client.get("/api/admin/compliance/requests").status_code == HTTPStatus.FORBIDDEN


def test_api_admin_compliance_requests_success(client, monkeypatch):
    login(client, ["user:all", "admin:all"])
    req = generate_class_instance(schema.AdminComplianceRequestResponse, seed=2)
    monkeypatch.setattr(server.orchestrator, "admin_fetch_compliance_requests", lambda at, page: _paginate([req]))

    response = client.get("/api/admin/compliance/requests")

    assert response.status_code == HTTPStatus.OK
    body = response.get_json()
    assert len(body["requests"]) == 1
    assert "created_by_user" in body["requests"][0]


# POST /api/compliance/requests (create)


def test_api_create_compliance_request_maps_payload(client, monkeypatch):
    login(client)
    captured = {}

    def fake_create(**kwargs):
        captured.update(kwargs)
        return generate_class_instance(schema.ComplianceRequestResponse, seed=3)

    monkeypatch.setattr(server.orchestrator, "create_compliance_request", fake_create)

    payload = {
        "csip_aus_version": "v1.3",
        "witnessed_at": "2024-06-15",
        "classes": ["DECEW", "DRGW"],
        "runs": [10, 11],
        "der_brand": "Acme",
        "der_oem": "OEM",
        "der_series": "S1",
        "der_representative_models": "M1, M2",
        "software_client_type": "direct",
        "software_client_providers": "P",
        "software_client_versions": "1.0",
        "onsite_hardware_details": "gateway",
    }
    response = client.post("/api/compliance/requests", json=payload)

    assert response.status_code == HTTPStatus.CREATED
    assert captured["classes"] == {"DECEW", "DRGW"}
    assert captured["runs"] == {10, 11}
    assert captured["witnessed_at"].tzinfo is not None
    assert captured["der_brand"] == "Acme"


def test_api_create_compliance_request_bad_request_on_missing_date(client, monkeypatch):
    login(client)
    monkeypatch.setattr(server.orchestrator, "create_compliance_request", lambda **kw: None)
    response = client.post("/api/compliance/requests", json={"classes": [], "runs": []})
    assert response.status_code == HTTPStatus.BAD_REQUEST


# PUT /api/compliance/requests/<id> (user update -> submitted)


def test_api_update_compliance_request_sets_submitted_status(client, monkeypatch):
    login(client)
    captured = {}

    def fake_update(at, request_id, body):
        captured["id"] = request_id
        captured["body"] = body
        return generate_class_instance(schema.ComplianceRequestResponse, seed=4)

    monkeypatch.setattr(server.orchestrator, "update_compliance_request", fake_update)

    response = client.put("/api/compliance/requests/7", json={"classes": ["DECEW"], "runs": [1]})

    assert response.status_code == HTTPStatus.OK
    assert captured["id"] == 7
    assert captured["body"].status == int(server.orchestrator.ComplianceRequestStatus.SUBMITTED)
    assert captured["body"].classes == {"DECEW"}


# PUT /api/admin/compliance/requests/<id> (admin review)


def test_api_admin_update_requires_valid_status(client, monkeypatch):
    login(client, ["user:all", "admin:all"])
    response = client.put("/api/admin/compliance/requests/7", json={"status": "bogus"})
    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_api_admin_update_pushed_back(client, monkeypatch):
    login(client, ["user:all", "admin:all"])
    captured = {}

    def fake_update(at, request_id, body):
        captured["body"] = body
        return generate_class_instance(schema.ComplianceRequestResponse, seed=5)

    monkeypatch.setattr(server.orchestrator, "admin_update_compliance_request", fake_update)

    response = client.put("/api/admin/compliance/requests/7", json={"status": "pushed_back"})

    assert response.status_code == HTTPStatus.OK
    assert captured["body"].status == int(server.orchestrator.ComplianceRequestStatus.PUSHED_BACK)


# DELETE


def test_api_delete_compliance_request(client, monkeypatch):
    login(client)
    monkeypatch.setattr(server.orchestrator, "delete_compliance_request", lambda at, rid: True)
    assert client.delete("/api/compliance/requests/7").status_code == HTTPStatus.OK


def test_api_admin_delete_forbidden_for_user(client):
    login(client, ["user:all"])
    assert client.delete("/api/admin/compliance/requests/7").status_code == HTTPStatus.FORBIDDEN


# GET /api/compliance/form-data


def test_api_compliance_form_data_success(client, monkeypatch):
    login(client)
    procedure = generate_class_instance(
        schema.TestProcedureResponse, seed=6, test_procedure_id="ALL-01", classes=["DECEW"], target_versions=["v1.3"]
    )
    run = generate_class_instance(schema.RunResponse, seed=7, test_procedure_id="ALL-01")
    monkeypatch.setattr(server, "fetch_all_test_procedures", lambda at: [procedure])
    monkeypatch.setattr(server.orchestrator, "fetch_ordered_successful_runs", lambda at: [run])

    response = client.get("/api/compliance/form-data")

    assert response.status_code == HTTPStatus.OK
    body = response.get_json()
    assert body["csipaus_versions"] == ["v1.3"]
    assert body["tests_by_version_and_class"]["v1.3"]["DECEW"] == ["ALL-01"]
    assert body["completed_test_procedures"] == ["ALL-01"]
    assert len(body["successful_runs"]) == 1
