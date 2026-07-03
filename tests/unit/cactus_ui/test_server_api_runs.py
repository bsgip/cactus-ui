from datetime import UTC, datetime, timedelta
from http import HTTPStatus

import cactus_schema.orchestrator as schema
import jwt
import pytest
from assertical.fake.generator import generate_class_instance

import cactus_ui.server as server
from cactus_ui.orchestrator import InitialiseRunFailureType, InitRunResult, StartResult


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


def single_page[T](items: list[T]) -> schema.Pagination[T]:
    return schema.Pagination(
        total_pages=1,
        total_items=len(items),
        page_size=10,
        current_page=1,
        prev_page=None,
        next_page=None,
        items=items,
    )


def expected_page_json(page: schema.Pagination) -> dict:
    return {
        "total_pages": page.total_pages,
        "total_items": page.total_items,
        "page_size": page.page_size,
        "current_page": page.current_page,
        "prev_page": page.prev_page,
        "next_page": page.next_page,
        "items": [i.to_dict() for i in page.items],
    }


def summary(test_procedure_id: str, category: str, classes: list[str] | None) -> schema.TestProcedureRunSummaryResponse:
    return generate_class_instance(
        schema.TestProcedureRunSummaryResponse,
        test_procedure_id=test_procedure_id,
        category=category,
        classes=classes,
    )


# /api/run_groups


def test_api_run_groups_unauthenticated(client):
    assert client.get("/api/run_groups").status_code == HTTPStatus.UNAUTHORIZED


def test_api_run_groups_success(client, monkeypatch):
    login(client)
    page = single_page([generate_class_instance(schema.RunGroupResponse, seed=i) for i in range(2)])
    monkeypatch.setattr(server.orchestrator, "fetch_run_groups", lambda access_token, p: page)

    response = client.get("/api/run_groups")

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_page_json(page)


def test_api_run_groups_orchestrator_failure(client, monkeypatch):
    login(client)
    monkeypatch.setattr(server.orchestrator, "fetch_run_groups", lambda access_token, p: None)

    response = client.get("/api/run_groups")

    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert response.get_json() == {"error": "Unable to fetch run groups."}


def test_api_admin_run_groups_forbidden_for_non_admin(client):
    login(client, ["user:all"])

    response = client.get("/api/admin/run_groups?run_group_id=1")

    assert response.status_code == HTTPStatus.FORBIDDEN
    assert response.get_json() == {"error": "forbidden"}


def test_api_admin_run_groups_requires_run_group_id(client):
    login(client, ["user:all", "admin:all"])

    response = client.get("/api/admin/run_groups")

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.get_json() == {"error": "run_group_id is required."}


def test_api_admin_run_groups_success(client, monkeypatch):
    login(client, ["user:all", "admin:all"])
    page = single_page([generate_class_instance(schema.RunGroupResponse)])
    calls = {}

    def fake_fetch(access_token, run_group_id, p):
        calls["run_group_id"] = run_group_id
        return page

    monkeypatch.setattr(server.orchestrator, "admin_fetch_run_groups", fake_fetch)

    response = client.get("/api/admin/run_groups?run_group_id=42")

    assert response.status_code == HTTPStatus.OK
    assert calls["run_group_id"] == 42
    assert response.get_json() == expected_page_json(page)


# /api/group/<id>/procedure_summaries


def test_api_procedure_summaries_groups_by_category(client, monkeypatch):
    login(client)
    procedures = [
        summary("ALL-01", "Generic", ["A", "G"]),
        summary("ALL-02", "Generic", ["A"]),
        summary("LOD-01", "Load Control", ["L"]),
        summary("LOD-02", "Load Control", None),
    ]
    monkeypatch.setattr(
        server.orchestrator, "fetch_group_procedure_run_summaries", lambda access_token, run_group_id: procedures
    )

    response = client.get("/api/group/1/procedure_summaries")

    assert response.status_code == HTTPStatus.OK
    body = response.get_json()
    assert [g["slug"] for g in body["grouped_procedures"]] == ["Generic", "Load-Control"]
    assert [g["category"] for g in body["grouped_procedures"]] == ["Generic", "Load Control"]
    assert [s["test_procedure_id"] for s in body["grouped_procedures"][0]["summaries"]] == ["ALL-01", "ALL-02"]
    assert [s["test_procedure_id"] for s in body["grouped_procedures"][1]["summaries"]] == ["LOD-01", "LOD-02"]
    assert body["classes_by_test"] == {"ALL-01": ["A", "G"], "ALL-02": ["A"], "LOD-01": ["L"], "LOD-02": []}
    assert body["classes_by_category"] == {"Generic": ["A", "G"], "Load-Control": ["L"]}
    # classes follow TS 5573 declaration order with descriptions
    assert [c["name"] for c in body["classes"]] == ["A", "G", "L"]
    assert all(c["description"] for c in body["classes"])


def test_api_procedure_summaries_orchestrator_failure(client, monkeypatch):
    login(client)
    monkeypatch.setattr(
        server.orchestrator, "fetch_group_procedure_run_summaries", lambda access_token, run_group_id: None
    )

    response = client.get("/api/group/1/procedure_summaries")

    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert response.get_json() == {"error": "Unable to fetch test procedures."}


def test_api_admin_procedure_summaries_forbidden_for_non_admin(client):
    login(client, ["user:all"])

    assert client.get("/api/admin/group/1/procedure_summaries").status_code == HTTPStatus.FORBIDDEN


def test_api_admin_procedure_summaries_success(client, monkeypatch):
    login(client, ["user:all", "admin:all"])
    monkeypatch.setattr(
        server.orchestrator,
        "admin_fetch_group_procedure_run_summaries",
        lambda access_token, run_group_id: [summary("ALL-01", "Generic", ["A"])],
    )

    response = client.get("/api/admin/group/1/procedure_summaries")

    assert response.status_code == HTTPStatus.OK
    assert [g["slug"] for g in response.get_json()["grouped_procedures"]] == ["Generic"]


# /api/group/<id>/procedure_runs/<tpid> and /api/group/<id>/active_runs


def test_api_procedure_runs_success(client, monkeypatch):
    login(client)
    page = single_page([generate_class_instance(schema.RunResponse, seed=i) for i in range(2)])
    monkeypatch.setattr(
        server.orchestrator,
        "fetch_group_runs_for_procedure",
        lambda access_token, run_group_id, test_procedure_id: page,
    )

    response = client.get("/api/group/1/procedure_runs/ALL-01")

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_page_json(page)


def test_api_procedure_runs_orchestrator_failure(client, monkeypatch):
    login(client)
    monkeypatch.setattr(
        server.orchestrator,
        "fetch_group_runs_for_procedure",
        lambda access_token, run_group_id, test_procedure_id: None,
    )

    response = client.get("/api/group/1/procedure_runs/ALL-01")

    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert response.get_json() == {"error": "Unable to fetch runs for ALL-01."}


def test_api_active_runs_requests_non_finalised_runs(client, monkeypatch):
    login(client)
    page = single_page([generate_class_instance(schema.RunResponse)])
    calls = {}

    def fake_fetch(access_token, run_group_id, p, finalised):
        calls["args"] = (run_group_id, p, finalised)
        return page

    monkeypatch.setattr(server.orchestrator, "fetch_runs_for_group", fake_fetch)

    response = client.get("/api/group/7/active_runs")

    assert response.status_code == HTTPStatus.OK
    assert calls["args"] == (7, 1, False)
    assert response.get_json() == expected_page_json(page)


def test_api_active_runs_orchestrator_failure(client, monkeypatch):
    login(client)
    monkeypatch.setattr(server.orchestrator, "fetch_runs_for_group", lambda access_token, run_group_id, p, f: None)

    response = client.get("/api/group/1/active_runs")

    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert response.get_json() == {"error": "Unable to load active runs."}


def test_api_admin_procedure_runs_and_active_runs_forbidden_for_non_admin(client):
    login(client, ["user:all"])

    assert client.get("/api/admin/group/1/procedure_runs/ALL-01").status_code == HTTPStatus.FORBIDDEN
    assert client.get("/api/admin/group/1/active_runs").status_code == HTTPStatus.FORBIDDEN


# POST /api/group/<id>/runs (initialise)


def test_api_init_run_success(client, monkeypatch):
    login(client)
    init_response = generate_class_instance(schema.InitRunResponse, run_id=55)
    monkeypatch.setattr(
        server.orchestrator,
        "init_run",
        lambda access_token, run_group_id, test_procedure_id: InitRunResult(
            response=init_response, failure_type=InitialiseRunFailureType.NO_FAILURE
        ),
    )

    response = client.post("/api/group/1/runs", json={"test_procedure_id": "ALL-01"})

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == {"run_id": 55}


def test_api_init_run_requires_test_procedure_id(client):
    login(client)

    response = client.post("/api/group/1/runs", json={})

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.get_json() == {"error": "No test procedure selected."}


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
            "Failed to trigger a new run due to an unknown error.",
        ),
    ],
)
def test_api_init_run_failures(client, monkeypatch, failure_type, status, error):
    login(client)
    monkeypatch.setattr(
        server.orchestrator,
        "init_run",
        lambda access_token, run_group_id, test_procedure_id: InitRunResult(response=None, failure_type=failure_type),
    )

    response = client.post("/api/group/1/runs", json={"test_procedure_id": "ALL-01"})

    assert response.status_code == status
    assert response.get_json() == {"error": error}


# POST /api/runs/<id>/start, /api/runs/<id>/finalise, DELETE /api/runs/<id>


def test_api_start_run_success(client, monkeypatch):
    login(client)
    monkeypatch.setattr(
        server.orchestrator, "start_run", lambda access_token, run_id: StartResult(success=True, error_message=None)
    )

    response = client.post("/api/runs/55/start")

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == {"run_id": 55}


@pytest.mark.parametrize(
    "error_message,expected",
    [("Precondition not met.", "Precondition not met."), (None, "Failed to start the test run.")],
)
def test_api_start_run_failure(client, monkeypatch, error_message, expected):
    login(client)
    monkeypatch.setattr(
        server.orchestrator,
        "start_run",
        lambda access_token, run_id: StartResult(success=False, error_message=error_message),
    )

    response = client.post("/api/runs/55/start")

    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert response.get_json() == {"error": expected}


def test_api_finalise_run(client, monkeypatch):
    login(client)
    monkeypatch.setattr(server.orchestrator, "finalise_run", lambda access_token, run_id: True)
    assert client.post("/api/runs/55/finalise").get_json() == {"run_id": 55}

    monkeypatch.setattr(server.orchestrator, "finalise_run", lambda access_token, run_id: False)
    response = client.post("/api/runs/55/finalise")
    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert response.get_json() == {"error": "Failed to finalise the run."}


def test_api_delete_run(client, monkeypatch):
    login(client)
    monkeypatch.setattr(server.orchestrator, "delete_individual_run", lambda access_token, run_id: True)
    assert client.delete("/api/runs/55").get_json() == {"run_id": 55}

    monkeypatch.setattr(server.orchestrator, "delete_individual_run", lambda access_token, run_id: False)
    response = client.delete("/api/runs/55")
    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert response.get_json() == {"error": "Failed to delete run."}


# Artifact downloads (browser-native GET routes)


def test_run_artifact_download_redirects_to_login_when_logged_out(client):
    response = client.get("/run/55/artifact")

    assert response.status_code == HTTPStatus.FOUND
    assert "/login" in response.headers["Location"]


def test_run_artifact_download_success(client, monkeypatch):
    login(client)
    monkeypatch.setattr(
        server.orchestrator, "fetch_run_artifact", lambda access_token, run_id: (b"zipbytes", "CACTUS-run-55.zip")
    )

    response = client.get("/run/55/artifact")

    assert response.status_code == HTTPStatus.OK
    assert response.data == b"zipbytes"
    assert response.mimetype == "application/zip"
    assert "CACTUS-run-55.zip" in response.headers["Content-Disposition"]


def test_run_artifact_download_failure(client, monkeypatch):
    login(client)
    monkeypatch.setattr(server.orchestrator, "fetch_run_artifact", lambda access_token, run_id: (None, ""))

    response = client.get("/run/55/artifact")

    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert b"Failed to retrieve artifacts." in response.data


def test_admin_run_artifact_download_redirects_non_admin(client):
    login(client, ["user:all"])

    response = client.get("/admin/run/55/artifact")

    assert response.status_code == HTTPStatus.FOUND


def test_admin_run_artifact_download_success(client, monkeypatch):
    login(client, ["user:all", "admin:all"])
    monkeypatch.setattr(
        server.orchestrator, "admin_fetch_run_artifact", lambda access_token, run_id: (b"zipbytes", "run-55.zip")
    )

    response = client.get("/admin/run/55/artifact")

    assert response.status_code == HTTPStatus.OK
    assert response.data == b"zipbytes"
