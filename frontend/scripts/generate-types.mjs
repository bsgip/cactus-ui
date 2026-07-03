// Converts the committed JSON Schema (frontend/src/api/generated/schema.json, produced by
// `uv run python scripts/export_api_schema.py`) into TypeScript. This is the frontend half
// of the type-generation pipeline; the Python dataclasses are the single source of truth.
//
// Run via `npm run generate:types`. CI runs it and `git diff --exit-code`s the output to
// catch drift. Do not hand-edit the generated file.

import { compile } from 'json-schema-to-typescript';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const schemaPath = resolve(here, '../src/api/generated/schema.json');
const outPath = resolve(here, '../src/api/generated/types.ts');

const banner = `/* eslint-disable */
/**
 * AUTO-GENERATED — DO NOT EDIT BY HAND.
 *
 * These types mirror the Python dataclasses that define the /api wire contract
 * (cactus_ui.api_models + cactus_schema runner/orchestrator schemas). Regenerate with:
 *   uv run python scripts/export_api_schema.py        # dataclasses -> schema.json
 *   (cd frontend && npm run generate:types)           # schema.json -> this file
 */`;

const schema = JSON.parse(readFileSync(schemaPath, 'utf8'));

let ts = await compile(schema, 'ApiSchemaRoot', {
  bannerComment: banner,
  additionalProperties: false,
  unreachableDefinitions: true,
  style: { singleQuote: true },
});

// Drop the empty container interface json2ts emits for the $defs-only root schema, plus the
// noisy "referenced by ApiSchemaRoot" back-reference comments it attaches to every def (both
// standalone comment blocks and the trailing lines appended inside real docstrings).
ts = ts.replace(/export interface ApiSchemaRoot \{[\s\S]*?\n\}\n/, '');
ts = ts.replace(/\/\*\*\n \* This interface was referenced[\s\S]*?\*\/\n/g, '');
ts = ts.replace(
  /\n \*\n \* This interface was referenced by[^\n]*\n \* via the `definition`[^\n]*\n/g,
  '\n'
);

writeFileSync(outPath, ts);
console.log(`Wrote ${outPath}`);
