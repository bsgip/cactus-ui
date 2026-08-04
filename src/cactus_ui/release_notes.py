import json
import logging
import time
from typing import Any, cast

import requests

logger = logging.getLogger(__name__)

RELEASES_URL = "https://api.github.com/repos/bsgip/cactus-deploy/releases"
RELEASES_HTML_URL = "https://github.com/bsgip/cactus-deploy/releases"
ASSET_NAME = "release-notes.json"
REQUEST_TIMEOUT_SECONDS = 10
CACHE_TTL_SECONDS = 15 * 60
RELEASES_LIMIT = 5  # how many releases the page shows

# Kept very simple: (expires_at, releases). The last good value is served indefinitely while GitHub is unreachable
_cache: tuple[float, list[dict[str, Any]]] | None = None


def _get_json(url: str) -> object | None:
    """GET url and parse it as JSON, or None on any failure. Never raises."""
    try:
        response = requests.get(url, headers={"Accept": "application/json"}, timeout=REQUEST_TIMEOUT_SECONDS)
    except requests.RequestException:
        logger.warning("release notes: request to %s failed", url, exc_info=True)
        return None

    if response.status_code != requests.codes.ok:
        logger.warning("release notes: %s returned HTTP %s", url, response.status_code)
        return None

    try:
        return response.json()
    except json.JSONDecodeError:
        logger.warning("release notes: %s returned unparseable JSON", url)
        return None


def _asset_url(release: dict[str, Any]) -> str | None:
    for asset in release.get("assets") or []:
        if isinstance(asset, dict) and asset.get("name") == ASSET_NAME:
            url = asset.get("browser_download_url")
            return url if isinstance(url, str) else None
    return None


def _fetch_release_notes() -> list[dict[str, Any]] | None:
    """The most recent releases carrying a release-notes.json asset, newest first.

    None means GitHub could not be reached; an empty list means it answered but nothing had the asset.
    """
    releases = _get_json(f"{RELEASES_URL}?per_page={RELEASES_LIMIT}")
    if not isinstance(releases, list):
        return None

    notes = []
    for release in releases:
        if not isinstance(release, dict):
            continue
        release = cast(dict[str, Any], release)
        asset_url = _asset_url(release)
        if asset_url is None:
            continue
        data = _get_json(asset_url)
        if not isinstance(data, dict):
            continue
        data = cast(dict[str, Any], data)
        # The asset knows the release's content; only GitHub knows how it was published.
        data["html_url"] = release.get("html_url")
        data["published_at"] = release.get("published_at")
        notes.append(data)
    return notes


def fetch_releases() -> list[dict[str, Any]]:
    """The most recent cactus-deploy releases as raw `release-notes.json` dicts, newest first."""
    global _cache

    now = time.monotonic()
    if _cache is not None and now < _cache[0]:
        return _cache[1]

    fetched = _fetch_release_notes()
    if fetched is None:
        return _cache[1] if _cache is not None else []

    _cache = (now + CACHE_TTL_SECONDS, fetched)
    return fetched


def clear_cache() -> None:
    """Drop the cached releases. For tests; nothing in the app invalidates the TTL early."""
    global _cache
    _cache = None
