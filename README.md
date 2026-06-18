# cactus-ui

User interface for the CSIP-Aus test harness.

A Vite + React 19 + TypeScript SPA (`frontend/`) served by a Flask backend-for-frontend
(`src/cactus_ui/`). Flask owns auth/session and exposes JSON under `/api/...`; React
handles everything the user sees.

## Frontend

All commands run from `frontend/`.

```bash
cd frontend
npm install            # first time, and after package.json changes
```

### Look at the UI locally

```bash
# No backend needed — MSW serves checked-in fixtures
npm run dev:mock       # http://localhost:5173

# Against the real Flask BFF — needs the cactus-ui-dev service + orchestrator tunnel up.
npm run dev            # http://localhost:5173, proxies /api etc. to Flask :3000
```

### Run tests

```bash
npm run test           # Vitest component tests (one-shot)
npm run test:watch     # Vitest in watch mode while developing
npm run test:e2e       # Playwright end-to-end (real browser)
```

### Checks before pushing

```bash
npm run typecheck      # tsc -b
npm run lint           # eslint
npm run test
```

### Production build

Outputs static files to `frontend/dist/`, which Flask serves (this is what the Dockerfile
runs):

```bash
npm run build          # tsc -b && vite build
npm run preview        # optional: serve the built dist/ to sanity-check it
```

## Backend
In normal use the Flask app runs as the `cactus-ui-dev` systemd service — you don't need
to start it by hand. For Python work:

```bash
uv sync --all-extras                 # from the repo root
uv run pytest tests/unit/...         # run only the relevant test files
uv run ruff check && uv run ty check
```