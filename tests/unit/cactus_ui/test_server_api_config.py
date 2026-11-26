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
        pen=123456,
    )
    rg = generate_class_instance(schema.RunGroupResponse, seed=0)
    run_groups = schema.Pagination(
        total_pages=1, total_items=1, page_size=10, current_page=1, prev_page=None, next_page=None, items=[rg]
    )
    version = generate_class_instance(schema.CSIPAusVersionResponse, seed=0)
    versions = schema.Pagination(
        total_pages=1, total_items=1, page_size=10, current_page=1, prev_page=None, next_page=None, items=[version]
    )

    certificates = [
        generate_class_instance(schema.CertificateResponse, seed=0),
        generate_class_instance(schema.CertificateResponse, seed=1),
    ]

    monkeypatch.setattr(server.orchestrator, "fetch_config", lambda at: config)
    monkeypatch.setattr(server.orchestrator, "fetch_run_groups", lambda at, p: run_groups)
    monkeypatch.setattr(server.orchestrator, "fetch_certificates", lambda at: certificates)
    monkeypatch.setattr(server.orchestrator, "fetch_csip_aus_versions", lambda at, p: versions)

    response = client.get("/api/config")

    assert response.status_code == HTTPStatus.OK
    body = response.get_json()
    assert body["config"]["subscription_domain"] == "my.example.com"
    assert body["config"]["pen"] == 123456
    assert len(body["run_groups"]) == 1
    assert [c["certificate_id"] for c in body["certificates"]] == [c.certificate_id for c in certificates]
    assert len(body["csip_aus_versions"]) == 1


def test_api_config_pen_zero_returns_null(client, monkeypatch):
    login(client)
    config = schema.UserConfigurationResponse(
        subscription_domain="",
        pen=0,
    )
    run_groups = schema.Pagination(
        total_pages=1, total_items=0, page_size=10, current_page=1, prev_page=None, next_page=None, items=[]
    )
    versions = schema.Pagination(
        total_pages=1, total_items=0, page_size=10, current_page=1, prev_page=None, next_page=None, items=[]
    )
    monkeypatch.setattr(server.orchestrator, "fetch_config", lambda at: config)
    monkeypatch.setattr(server.orchestrator, "fetch_run_groups", lambda at, p: run_groups)
    monkeypatch.setattr(server.orchestrator, "fetch_certificates", lambda at: [])
    monkeypatch.setattr(server.orchestrator, "fetch_csip_aus_versions", lambda at, p: versions)

    response = client.get("/api/config")

    assert response.status_code == HTTPStatus.OK
    assert response.get_json()["config"]["pen"] is None
    assert response.get_json()["certificates"] == []


@pytest.mark.parametrize(
    "failing", ["fetch_config", "fetch_run_groups", "fetch_certificates", "fetch_csip_aus_versions"]
)
def test_api_config_orchestrator_failure(client, monkeypatch, failing: str):
    login(client)
    empty_page = schema.Pagination(
        total_pages=1, total_items=0, page_size=10, current_page=1, prev_page=None, next_page=None, items=[]
    )
    monkeypatch.setattr(server.orchestrator, "fetch_config", lambda at: schema.UserConfigurationResponse("", 0))
    monkeypatch.setattr(server.orchestrator, "fetch_run_groups", lambda at, p: empty_page)
    monkeypatch.setattr(server.orchestrator, "fetch_certificates", lambda at: [])
    monkeypatch.setattr(server.orchestrator, "fetch_csip_aus_versions", lambda at, p: empty_page)
    monkeypatch.setattr(server.orchestrator, failing, lambda *args: None)

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


# /api/run_groups POST (create)


def test_api_create_run_group_success(client, monkeypatch):
    login(client)
    rg = generate_class_instance(schema.RunGroupResponse, seed=0)
    calls = {}
    monkeypatch.setattr(
        server.orchestrator,
        "create_run_group",
        lambda at, ver: calls.update({"ver": ver}) or rg,
    )

    response = client.post("/api/run_groups", json={"csip_aus_version": "v1.2"})

    assert response.status_code == HTTPStatus.CREATED
    assert response.get_json()["run_group_id"] == rg.run_group_id
    assert calls["ver"] == "v1.2"


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
        server.orchestrator, "update_run_group", lambda at, rid, **kw: calls.update({"rid": rid, **kw}) or rg
    )

    response = client.patch("/api/run_groups/5", json={"name": "New Name"})

    assert response.status_code == HTTPStatus.OK
    assert calls["rid"] == 5
    assert calls["name"] == "New Name"


def test_api_update_run_group_missing_fields(client):
    login(client)

    response = client.patch("/api/run_groups/1", json={})

    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_api_update_run_group_orchestrator_failure(client, monkeypatch):
    login(client)
    monkeypatch.setattr(server.orchestrator, "update_run_group", lambda at, rid, **kw: None)

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


# Certificates


def file_result(content: bytes | None, file_name: str | None, certificate_id: int | None, error: str | None = None):
    return server.orchestrator.CertificateFileResult(content, file_name, certificate_id, error)


@pytest.mark.parametrize(
    "body, expected_is_device_cert, assign_failures, expected_assigned, expected_unassigned_header",
    [
        ({"name": "My cert", "type": "device"}, True, set(), [], None),
        ({"name": " Agg ", "type": "aggregator", "run_group_ids": [3, 4]}, False, set(), [3, 4], None),
        ({"name": "Agg", "type": "aggregator", "run_group_ids": ["3", 4, 5]}, False, {4}, [3, 4, 5], "4"),
    ],
)
def test_config_create_certificate_success(
    client, monkeypatch, body, expected_is_device_cert, assign_failures, expected_assigned, expected_unassigned_header
):
    login(client)
    created = {}
    assigned = []
    rg = generate_class_instance(schema.RunGroupResponse, seed=1)

    def create(at, name, is_device_cert):
        created.update({"name": name, "is_device_cert": is_device_cert})
        return file_result(b"zip-bytes", "cert.zip", 42)

    def assign(at, run_group_id, certificate_id):
        assigned.append((run_group_id, certificate_id))
        return None if run_group_id in assign_failures else rg

    monkeypatch.setattr(server.orchestrator, "create_certificate", create)
    monkeypatch.setattr(server.orchestrator, "assign_run_group_certificate", assign)

    response = client.post("/config/certificates", json=body)

    assert response.status_code == HTTPStatus.OK
    assert response.data == b"zip-bytes"
    assert response.mimetype == "application/zip"
    assert "cert.zip" in response.headers["Content-Disposition"]
    assert created == {"name": body["name"].strip(), "is_device_cert": expected_is_device_cert}
    assert assigned == [(rg_id, 42) for rg_id in expected_assigned]
    assert response.headers.get(server.HEADER_UNASSIGNED_RUN_GROUPS) == expected_unassigned_header


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"name": "  ", "type": "device"},
        {"name": "x", "type": "other"},
        {"name": "x", "type": "device", "run_group_ids": ["abc"]},
    ],
)
def test_config_create_certificate_bad_request(client, monkeypatch, body):
    login(client)
    monkeypatch.setattr(server.orchestrator, "create_certificate", lambda *args: pytest.fail("Shouldn't be called"))

    response = client.post("/config/certificates", json=body)

    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_config_create_certificate_orchestrator_failure(client, monkeypatch):
    login(client)
    monkeypatch.setattr(
        server.orchestrator, "create_certificate", lambda *args: file_result(None, None, None, "Set a domain first.")
    )
    monkeypatch.setattr(
        server.orchestrator, "assign_run_group_certificate", lambda *args: pytest.fail("Shouldn't be called")
    )

    response = client.post("/config/certificates", json={"name": "x", "type": "aggregator", "run_group_ids": [1]})

    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert response.get_data(as_text=True) == "Set a domain first."


def test_config_create_certificate_unauthenticated(client):
    response = client.post("/config/certificates", json={"name": "x", "type": "device"})
    assert response.status_code != HTTPStatus.OK


@pytest.mark.parametrize(
    "url, method, orchestrator_fn, expected_mimetype",
    [
        ("/config/certificates/7", "GET", "download_certificate", "application/x-pem-file"),
        ("/config/certificates/7/regenerate", "POST", "regenerate_certificate", "application/zip"),
    ],
)
def test_config_certificate_file_routes(client, monkeypatch, url, method, orchestrator_fn, expected_mimetype):
    login(client)
    calls = []
    monkeypatch.setattr(
        server.orchestrator,
        orchestrator_fn,
        lambda at, cid: calls.append(cid) or file_result(b"file-bytes", "file.name", cid),
    )

    response = client.open(url, method=method)

    assert response.status_code == HTTPStatus.OK
    assert response.data == b"file-bytes"
    assert response.mimetype == expected_mimetype
    assert calls == [7]

    # And the failure path
    monkeypatch.setattr(server.orchestrator, orchestrator_fn, lambda at, cid: file_result(None, None, None, "boom"))
    response = client.open(url, method=method)
    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert response.get_data(as_text=True) == "boom"


def test_api_delete_certificate(client, monkeypatch):
    login(client)
    calls = []
    monkeypatch.setattr(
        server.orchestrator,
        "delete_certificate",
        lambda at, cid: calls.append(cid) or server.orchestrator.ActionResult(True, None),
    )
    response = client.delete("/api/certificates/9")
    assert response.status_code == HTTPStatus.OK
    assert calls == [9]

    monkeypatch.setattr(
        server.orchestrator,
        "delete_certificate",
        lambda at, cid: server.orchestrator.ActionResult(False, "In use by active run(s) 5."),
    )
    response = client.delete("/api/certificates/9")
    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert response.get_json() == {"error": "In use by active run(s) 5."}


def test_api_assign_run_group_certificate(client, monkeypatch):
    login(client)
    rg = generate_class_instance(schema.RunGroupResponse, seed=1)
    calls = []
    monkeypatch.setattr(
        server.orchestrator, "assign_run_group_certificate", lambda at, rid, cid: calls.append((rid, cid)) or rg
    )

    response = client.put("/api/run_groups/3/certificate", json={"certificate_id": 12})
    assert response.status_code == HTTPStatus.OK
    assert response.get_json()["run_group_id"] == rg.run_group_id
    assert calls == [(3, 12)]

    assert client.put("/api/run_groups/3/certificate", json={}).status_code == HTTPStatus.BAD_REQUEST
    assert (
        client.put("/api/run_groups/3/certificate", json={"certificate_id": "x"}).status_code == HTTPStatus.BAD_REQUEST
    )

    monkeypatch.setattr(server.orchestrator, "assign_run_group_certificate", lambda *args: None)
    response = client.put("/api/run_groups/3/certificate", json={"certificate_id": 12})
    assert response.status_code == HTTPStatus.BAD_GATEWAY


def test_api_unassign_run_group_certificate(client, monkeypatch):
    login(client)
    rg = generate_class_instance(schema.RunGroupResponse, seed=1, optional_is_none=True)
    calls = []
    monkeypatch.setattr(server.orchestrator, "unassign_run_group_certificate", lambda at, rid: calls.append(rid) or rg)

    response = client.delete("/api/run_groups/3/certificate")
    assert response.status_code == HTTPStatus.OK
    assert response.get_json()["assigned_certificate_id"] is None
    assert calls == [3]

    monkeypatch.setattr(server.orchestrator, "unassign_run_group_certificate", lambda *args: None)
    assert client.delete("/api/run_groups/3/certificate").status_code == HTTPStatus.BAD_GATEWAY


def test_legacy_certificate_routes_removed(client):
    login(client)
    assert client.post("/config/shared_cert").status_code in (HTTPStatus.NOT_FOUND, HTTPStatus.METHOD_NOT_ALLOWED)
    assert client.post("/config/run_group/1/cert").status_code in (
        HTTPStatus.NOT_FOUND,
        HTTPStatus.METHOD_NOT_ALLOWED,
    )
