# cactus-ui

User interface for the CSIP-Aus test harness.
A Vite + React 19 + TypeScript SPA (`frontend/`) served by a Flask backend-for-frontend (BFF) (`src/cactus_ui/`).

## Running locally

Ensure you have the correct version of Node.js:

```bash
node -v          # should be 22.x+
# If not:
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs
```

Install dependencies after any `package.json` / `pyproject.toml` change:

```bash
npm install      # frontend deps (from /frontend)
uv sync --all-extras            # backend deps (from repo root)
```

The backend reads config from a `.env` file in the repo root. Copy the sample and fill it
in:

```bash
cp .sampleenv .env              # keep CACTUS_UI_LOCALDEV=true for local runs
```

There are 3 ways to get the UI up.

### 1. Frontend only, no backend (mock mode)

The fastest way to look at and iterate on the UI. MSW intercepts every `/api` call and answers from fixtures.

```bash
cd frontend
npm run dev:mock                # http://localhost:5173, served from fixtures
npm run dev:mock:admin          # same, but signed in as an admin-scoped user
```

Fixtures live in `frontend/src/mocks/` (`handlers.ts`).

### 2. Full stack (Point at a real orchestrator backend)

Requires:
CACTUS_ORCHESTRATOR_BASEURL set in the env file to a port forwarded tunnel to the orchestrator.
Valid Auth0 settings in `.env` (see sample.env).

```bash
cd frontend && npm run build
uv run python src/cactus_ui/server.py   # http://localhost:3000
```

### 3. Frontend hot-reload against the real backend (I cant seem to get this working but it should :P)

If you want live reload *and* real data, run Flask (as above) and Vite side by side. Vite proxies the Flask-owned paths to `:3000`:

```bash
uv run python src/cactus_ui/server.py   # terminal 1 — Flask on :3000
cd frontend && npm run dev              # terminal 2 — http://localhost:5173
```

## Tests

### Frontend

```bash
cd frontend
npm run test                    # Vitest component tests (one-shot)
npm run test:watch              # watch mode while developing
```

### Backend

```bash
uv run pytest # From /src
```

### Linting/Formatting

```bash
# frontend (from frontend/)
npm run typecheck               # tsc -b
npm run lint                    # eslint
npm run test

# backend (from repo root)
uv run ruff check
uv run ruff format
uv run ty check
```
