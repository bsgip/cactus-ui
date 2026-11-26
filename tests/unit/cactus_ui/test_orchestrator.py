import json
from pathlib import Path

import cactus_schema.orchestrator as orchestrator
import pytest
from assertical.fake.generator import generate_class_instance
from cactus_schema.orchestrator import CertificateResponse, RunGroupResponse

import cactus_ui.orchestrator as ui_orchestrator
from cactus_ui.orchestrator import file_name_safe, handle_pagination

FIXTURES_DIR = Path(__file__).resolve().parents[3] / "frontend" / "fixtures"


@pytest.mark.parametrize(
    "input, expected", [("", ""), ("hello-VALID_123", "hello-VALID_123"), ("abc 123@DEF./com", "abc_123_DEF__com")]
)
def test_file_name_safe(input: str, expected: str):
    assert file_name_safe(input) == expected


@pytest.mark.parametrize(
    "total_pages, current_page, prev_page, next_page",
    [(1, 1, None, None), (3, 2, 1, 3), (3, 3, 2, None)],
)
def test_handle_pagination(total_pages: int, current_page: int, prev_page: int | None, next_page: int | None):
    paginated_json = {
        "total_pages": total_pages,
        "total_items": 25,
        "page_size": 10,
        "current_page": current_page,
        "prev_page": prev_page,
        "next_page": next_page,
        "items": [{"version": "v1.2"}, {"version": "v1.3"}],
    }

    result = handle_pagination(paginated_json, lambda i: orchestrator.CSIPAusVersionResponse.from_dict(i))

    assert isinstance(result, orchestrator.Pagination)
    assert result.total_pages == total_pages
    assert result.total_items == 25
    assert result.page_size == 10
    assert result.current_page == current_page
    assert result.prev_page == prev_page
    assert result.next_page == next_page
    assert [i.version for i in result.items] == ["v1.2", "v1.3"]
    assert all(isinstance(i, orchestrator.CSIPAusVersionResponse) for i in result.items)


def test_handle_pagination_fixture():
    """A recorded Pagination[RunResponse] payload parses into fully typed items"""
    paginated_json = json.loads((FIXTURES_DIR / "procedure_runs.json").read_text())

    result = handle_pagination(paginated_json, lambda r: orchestrator.RunResponse.from_dict(r))

    assert result.total_items == paginated_json["total_items"]
    assert len(result.items) == len(paginated_json["items"])
    assert all(isinstance(i, orchestrator.RunResponse) for i in result.items)


def test_handle_pagination_legacy_schema_fails_loudly():
    """The old fastapi-pagination shape (pages/page/size/total) must not silently parse as a single page"""
    legacy_json = {"items": [], "total": 25, "page": 2, "size": 10, "pages": 3}
    with pytest.raises(KeyError):
        handle_pagination(legacy_json, lambda i: i)


class FakeResponse:
    def __init__(self, status_code: int, json_body=None, headers: dict | None = None, content: bytes = b""):
        self.status_code = status_code
        self._json_body = json_body
        self.headers = headers or {}
        self.content = content
        self.text = json.dumps(json_body) if json_body is not None else ""

    def json(self):
        if self._json_body is None:
            raise ValueError("No JSON")
        return self._json_body


@pytest.mark.parametrize(
    "location, expected",
    [("/certificate/12", 12), ("http://host/certificate/3/", 3), (None, None), ("", None), ("/certificate/abc", None)],
)
def test_parse_certificate_id(location, expected):
    assert ui_orchestrator._parse_certificate_id(location) == expected


@pytest.mark.parametrize(
    "response, expected",
    [
        (None, "default"),
        (FakeResponse(409, {"detail": "In use"}), "In use"),
        (FakeResponse(422, {"detail": [{"msg": "bad"}]}), "default"),  # FastAPI validation errors aren't strings
        (FakeResponse(500), "default"),
    ],
)
def test_try_read_error_detail(response, expected):
    assert ui_orchestrator.try_read_error_detail(response, "default") == expected


def test_fetch_certificates_follows_pagination(monkeypatch):
    certs = [generate_class_instance(CertificateResponse, seed=i) for i in range(3)]

    def page(items, current_page, next_page):
        return {
            "total_pages": 2,
            "total_items": 3,
            "page_size": 2,
            "current_page": current_page,
            "prev_page": None,
            "next_page": next_page,
            "items": [c.to_dict() for c in items],
        }

    urls = []
    responses = [FakeResponse(200, page(certs[:2], 1, 2)), FakeResponse(200, page(certs[2:], 2, None))]
    monkeypatch.setattr(
        ui_orchestrator, "safe_request", lambda method, url, *a, **kw: urls.append(url) or responses.pop(0)
    )

    assert ui_orchestrator.fetch_certificates("token") == certs
    assert [u.split("?")[1] for u in urls] == ["page=1&size=100", "page=2&size=100"]

    monkeypatch.setattr(ui_orchestrator, "safe_request", lambda *a, **kw: FakeResponse(500))
    assert ui_orchestrator.fetch_certificates("token") is None


def test_create_certificate(monkeypatch):
    calls = []
    monkeypatch.setattr(
        ui_orchestrator,
        "safe_request",
        lambda method, url, headers, timeout, json=None: (
            calls.append((method, url, json))
            or FakeResponse(
                201,
                headers={"Location": "/certificate/7", "Content-Disposition": "attachment; filename=x-Device-1.zip"},
                content=b"zip",
            )
        ),
    )
    result = ui_orchestrator.create_certificate("token", "x", True)
    assert result == ui_orchestrator.CertificateFileResult(b"zip", "x-Device-1.zip", 7, None)
    assert calls[0][0] == "POST" and calls[0][1].endswith("/certificate")
    assert calls[0][2] == {"name": "x", "is_device_cert": True}

    monkeypatch.setattr(ui_orchestrator, "safe_request", lambda *a, **kw: FakeResponse(400, {"detail": "Need domain"}))
    assert ui_orchestrator.create_certificate("token", "x", False) == ui_orchestrator.CertificateFileResult(
        None, None, None, "Need domain"
    )


def test_delete_certificate(monkeypatch):
    monkeypatch.setattr(ui_orchestrator, "safe_request", lambda *a, **kw: FakeResponse(204))
    assert ui_orchestrator.delete_certificate("token", 1) == ui_orchestrator.ActionResult(True, None)

    monkeypatch.setattr(ui_orchestrator, "safe_request", lambda *a, **kw: FakeResponse(409, {"detail": "Active runs"}))
    assert ui_orchestrator.delete_certificate("token", 1) == ui_orchestrator.ActionResult(False, "Active runs")

    monkeypatch.setattr(ui_orchestrator, "safe_request", lambda *a, **kw: None)
    assert ui_orchestrator.delete_certificate("token", 1) == ui_orchestrator.ActionResult(
        False, "Failed to delete certificate."
    )


@pytest.mark.parametrize("assign", [True, False])
def test_assign_unassign_run_group_certificate(monkeypatch, assign: bool):
    rg = generate_class_instance(RunGroupResponse, seed=1)
    calls = []
    monkeypatch.setattr(
        ui_orchestrator,
        "safe_request",
        lambda method, url, headers, timeout, json=None: (
            calls.append((method, url, json)) or FakeResponse(200, rg.to_dict())
        ),
    )
    if assign:
        assert ui_orchestrator.assign_run_group_certificate("token", 4, 9) == rg
        assert calls == [("PUT", ui_orchestrator.generate_uri("/run_group/4/certificate"), {"certificate_id": 9})]
    else:
        assert ui_orchestrator.unassign_run_group_certificate("token", 4) == rg
        assert calls == [("DELETE", ui_orchestrator.generate_uri("/run_group/4/certificate"), None)]

    monkeypatch.setattr(ui_orchestrator, "safe_request", lambda *a, **kw: FakeResponse(404))
    if assign:
        assert ui_orchestrator.assign_run_group_certificate("token", 4, 9) is None
    else:
        assert ui_orchestrator.unassign_run_group_certificate("token", 4) is None
