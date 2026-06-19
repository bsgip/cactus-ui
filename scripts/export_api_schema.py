"""Export a JSON Schema for the `/api` run-status response shapes.

This is the Python half of the type-generation pipeline. It walks a fixed set of
response dataclasses — the BFF-assembled shapes from `cactus_ui.api_models` plus the
pass-through cactus-schema dataclasses the run-status page consumes — and emits a single
JSON Schema (with shared `$defs`) to `frontend/src/api/generated/schema.json`.

The frontend's `npm run generate:types` then converts that schema into TypeScript, so the
dataclasses are the single source of truth and `types.ts` is never hand-edited.

Pydantic is only used here (and in the fixture test), at codegen time — nothing at runtime
depends on it. Run with `uv run python scripts/export_api_schema.py`; CI regenerates and
diffs the output to catch drift.
"""

import json
from pathlib import Path

from cactus_schema.orchestrator.schema import ProceedResponse
from cactus_schema.runner.schema import RequestData, RunnerStatus
from pydantic import TypeAdapter
from pydantic.json_schema import GenerateJsonSchema

from cactus_ui.api_models import RunStatusShell

# Top-level response types the run-status page depends on. Nested types (the embedded
# RunResponse/PlaylistRunInfo, RunnerStatus's DER*/timeline entries, etc.) are pulled in
# automatically as shared `$defs`.
RESPONSE_TYPES = [
    RunStatusShell,
    RunnerStatus,
    RequestData,
    ProceedResponse,
]

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "frontend" / "src" / "api" / "generated" / "schema.json"


def _strip_titles(node: object) -> None:
    """Drop pydantic's per-field `title`s. They make json-schema-to-typescript promote
    every property into its own noisy named alias; the `$defs` keys are the names we want.
    """
    if isinstance(node, dict):
        node.pop("title", None)
        for value in node.values():
            _strip_titles(value)
    elif isinstance(node, list):
        for value in node:
            _strip_titles(value)


def _require_all_properties(node: object) -> None:
    """Mark every object property as `required`.

    Pydantic marks fields with defaults as optional, but the wire serializer
    (dataclass_wizard / FastAPI) always emits every field — a default of `None` becomes an
    explicit `null`, not an absent key. So on the wire these fields are always present; the
    generated TS should treat them as required-but-nullable (`T | null`), not `T | undefined`.
    """
    if isinstance(node, dict):
        properties = node.get("properties")
        if isinstance(properties, dict):
            node["required"] = sorted(properties)
        for value in node.values():
            _require_all_properties(value)
    elif isinstance(node, list):
        for value in node:
            _require_all_properties(value)


def build_schema() -> dict:
    defs: dict = {}
    for response_type in RESPONSE_TYPES:
        schema = TypeAdapter(response_type).json_schema(
            ref_template="#/$defs/{model}", schema_generator=GenerateJsonSchema
        )
        defs.update(schema.pop("$defs", {}))
        defs[response_type.__name__] = schema
    _strip_titles(defs)
    _require_all_properties(defs)
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$defs": dict(sorted(defs.items())),
    }


def main() -> None:
    schema = build_schema()
    SCHEMA_PATH.parent.mkdir(parents=True, exist_ok=True)
    SCHEMA_PATH.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n")
    print(f"Wrote {SCHEMA_PATH.relative_to(Path.cwd())}")


if __name__ == "__main__":
    main()
