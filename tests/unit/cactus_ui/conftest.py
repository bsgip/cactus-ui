"""Fixtures shared across cactus_ui unit tests."""

from typing import Any

import pytest


@pytest.fixture
def release_asset() -> dict[str, Any]:
    """A release-notes.json asset for release-177, as cactus-deploy's workflow would emit it.

    Fresh per test.
    """
    return {
        "tag": "release-177",
        "previous_tag": "release-176",
        "components": [
            {
                "name": "Orchestrator",
                "repo": "bsgip/cactus-orchestrator",
                "previous": "v2.2.0",
                "current": "v2.2.1",
                "changed": True,
                "changes": [
                    {
                        "title": "Add .well-known route to traefik",
                        "pr": 185,
                        "url": "https://github.com/bsgip/cactus-orchestrator/pull/185",
                    }
                ],
                "notes": [],
            }
        ],
        "test_definitions": None,
        "warnings": [],
    }
