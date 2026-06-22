"""Typed shapes for the BFF-assembled `/api` JSON responses.

Most `/api` responses are cactus-schema types forwarded as-is (the BFF is a thin proxy). The
only genuinely BFF-owned shape is a small envelope that embeds a canonical type and adds the
handful of fields the orchestrator doesn't provide (derived/joined data). Defining it here
(rather than re-typing pass-through fields) keeps it a thin envelope, not a translation layer.

`server.py` constructs and `.to_dict()`s these; `scripts/export_api_schema.py` reads them (with
the embedded cactus-schema types) to generate the frontend's TypeScript.
"""

from dataclasses import dataclass

from cactus_schema.orchestrator.schema import FastAPICompatibleWizard, RunResponse


@dataclass
class RunStatusShell(FastAPICompatibleWizard):
    """Run-status page shell: the run plus the few extras the orchestrator doesn't supply.

    `run` and `playlist_runs` are canonical `RunResponse`s (no reshaping/renaming) — the
    frontend reads their fields directly and derives playlist order / active-run / next-run
    itself. The remaining fields are things only the BFF knows or computes.
    """

    run: RunResponse | None  # the run, forwarded as-is
    run_is_live: bool  # derived: a runner status exists, or status is provisioning/started
    # DEBT: this duplicates RunResponse.immediate_start, which exists upstream but not in the
    # pinned cactus-schema. Drop this field and read `run.immediate_start` after the next bump.
    is_immediate_start: bool
    playlist_name: str | None  # playlist display name (from the Flask session; not on any run)
    playlist_runs: list[RunResponse] | None  # all runs in the playlist, fetched and joined
