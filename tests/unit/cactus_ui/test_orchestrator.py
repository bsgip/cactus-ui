import json
from pathlib import Path

import cactus_schema.orchestrator as orchestrator
import pytest

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
