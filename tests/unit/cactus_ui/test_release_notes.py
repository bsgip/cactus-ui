"""Tests for the GitHub release-notes fetcher and its presenter.

The fetcher's whole job is to be un-droppable: GitHub is a third party on the page-load path,
so the interesting cases are the failure ones (unreachable, non-200, junk JSON, missing asset)
and the cache that keeps a bad minute from emptying the page.
"""

import json
from datetime import UTC, datetime
from http import HTTPStatus

import pytest
import requests
from cactus_schema.orchestrator import DeployReleaseResponse

import cactus_ui.release_notes as release_notes
from cactus_ui.presenters import build_release_notes

ASSET_URL = "https://github.com/bsgip/cactus-deploy/releases/download/release-177/release-notes.json"

RELEASE = {
    "tag_name": "release-177",
    "html_url": "https://github.com/bsgip/cactus-deploy/releases/tag/release-177",
    "published_at": "2026-07-24T06:48:51Z",
    "assets": [{"name": "release-notes.json", "browser_download_url": ASSET_URL}],
}


class FakeResponse:
    def __init__(self, payload, status_code=HTTPStatus.OK):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        if isinstance(self._payload, str):
            raise json.JSONDecodeError("expecting value", self._payload, 0)
        return self._payload


def fake_get(responses: dict[str, object]):
    """Serve canned responses keyed by URL prefix; anything unexpected raises."""

    def get(url, **kwargs):
        for prefix, response in responses.items():
            if url.startswith(prefix):
                if isinstance(response, Exception):
                    raise response
                return response
        raise AssertionError(f"unexpected request to {url}")

    return get


@pytest.fixture(autouse=True)
def clear_cache():
    release_notes.clear_cache()
    yield
    release_notes.clear_cache()


def test_fetch_releases_returns_current_release_and_skips_pre_cutover_ones(monkeypatch, release_asset):
    """Everything published before the workflow rework has no asset - those aren't shown."""
    old_release = {"tag_name": "release-150", "html_url": "https://example.com", "assets": []}
    monkeypatch.setattr(
        requests,
        "get",
        fake_get(
            {release_notes.RELEASES_URL: FakeResponse([old_release, RELEASE]), ASSET_URL: FakeResponse(release_asset)}
        ),
    )

    releases = release_notes.fetch_releases()

    assert [r["tag"] for r in releases] == ["release-177"]
    # The asset knows the content; only the GitHub release knows where/when it was published.
    assert releases[0]["html_url"] == RELEASE["html_url"]
    assert releases[0]["published_at"] == RELEASE["published_at"]


@pytest.mark.parametrize(
    "listing",
    [
        FakeResponse(None, HTTPStatus.FORBIDDEN),  # rate limited
        FakeResponse("not json"),
        FakeResponse({"message": "Not Found"}),  # 200 but not a list
        requests.ConnectionError("no route to host"),
    ],
)
def test_fetch_releases_degrades_to_empty_when_github_fails(monkeypatch, listing):
    monkeypatch.setattr(requests, "get", fake_get({release_notes.RELEASES_URL: listing}))

    assert release_notes.fetch_releases() == []


def test_fetch_releases_serves_the_last_good_value_when_github_fails(monkeypatch, release_asset):
    """A failing fetch must not empty a page that was populated a minute ago."""
    monkeypatch.setattr(
        requests,
        "get",
        fake_get({release_notes.RELEASES_URL: FakeResponse([RELEASE]), ASSET_URL: FakeResponse(release_asset)}),
    )
    assert len(release_notes.fetch_releases()) == 1

    monkeypatch.setattr(requests, "get", fake_get({release_notes.RELEASES_URL: requests.Timeout()}))
    monkeypatch.setattr(release_notes.time, "monotonic", lambda: 1e9)  # past the TTL

    assert [r["tag"] for r in release_notes.fetch_releases()] == ["release-177"]


def test_fetch_releases_caches_within_the_ttl(monkeypatch, release_asset):
    calls = []

    def counting_get(url, **kwargs):
        calls.append(url)
        return FakeResponse([RELEASE] if url.startswith(release_notes.RELEASES_URL) else release_asset)

    monkeypatch.setattr(requests, "get", counting_get)

    release_notes.fetch_releases()
    release_notes.fetch_releases()

    assert len(calls) == 2  # the listing and its one asset, fetched once


def test_build_release_notes_parses_the_asset(release_asset):
    response = build_release_notes([release_asset | {"html_url": RELEASE["html_url"]}], [])

    release = response.releases[0]
    assert release.tag == "release-177"
    assert release.html_url == RELEASE["html_url"]
    assert release.deployed_at is None  # no deploy history
    component = release.components[0]
    assert component.name == "Orchestrator"
    assert component.changes[0].pr == 185


@pytest.mark.parametrize(
    ("deploys", "expected_deployed_at_index"),
    [
        pytest.param(
            [DeployReleaseResponse(release_tag="177", created_at=datetime(2026, 7, 26, 4, 30, tzinfo=UTC))],
            0,
            id="matches-release-tag-to-image-tag",
        ),
        pytest.param(
            [
                DeployReleaseResponse(release_tag="177", created_at=datetime(2026, 7, 27, 22, 5, tzinfo=UTC)),
                DeployReleaseResponse(release_tag="178", created_at=datetime(2026, 7, 27, 1, 10, tzinfo=UTC)),
                DeployReleaseResponse(release_tag="177", created_at=datetime(2026, 7, 26, 4, 30, tzinfo=UTC)),
            ],
            0,
            id="rolled-back-tag-uses-most-recent-deploy",
        ),
    ],
)
def test_build_release_notes_matches_deploys_by_tag(deploys, expected_deployed_at_index, release_asset):
    """update.sh records the orchestrator image tag (`177`); the release is tagged `release-177`.

    A tag deployed, rolled away from, then redeployed (second case) shows when it was last live.
    """
    response = build_release_notes([release_asset], deploys)

    assert response.releases[0].deployed_at == deploys[expected_deployed_at_index].created_at
    # The history itself is passed through untouched so the page can show a rollback.
    assert [d.release_tag for d in response.deploy_history] == [d.release_tag for d in deploys]


def test_build_release_notes_skips_an_unparseable_asset(release_asset):
    response = build_release_notes([{"tag": "release-178", "components": "not a list"}, release_asset], [])
    assert [r.tag for r in response.releases] == ["release-177"]


def test_build_release_notes_maps_test_definitions(release_asset):
    asset = release_asset | {
        "test_definitions": {
            "previous": "1.14.8",
            "current": "1.15.0",
            "procedures": {"modified": 32, "added": 1, "removed": 0, "total": 82},
            "changes": [],
            "notes": [],
        }
    }

    test_definitions = build_release_notes([asset], []).releases[0].test_definitions

    assert test_definitions is not None
    assert test_definitions.procedures is not None
    assert test_definitions.procedures.modified == 32
    assert test_definitions.current == "1.15.0"
