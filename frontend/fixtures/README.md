# Fixtures

Recorded JSON responses from the Flask BFF `/api` endpoints, served by MSW in Vitest,
Playwright, and `npm run dev:mock`. One file per endpoint (plus variants, e.g.
`session_admin.json`).

When an endpoint's response shape changes, update its fixture in the same PR.

## Capturing / refreshing a fixture

1. Bring up the live stack (orchestrator tunnel + `cactus-ui-dev` service — see
   MIGRATION.md "Live Environment") and log in at `http://localhost:3000` via the
   SSH tunnel from your dev machine.
2. In the browser dev tools (Network tab), open the `/api/...` request and copy the
   response JSON; or copy the `session` cookie and run on the VM:

   ```bash
   curl -s -H "Cookie: session=<cookie>" http://localhost:3000/api/session | python3 -m json.tool
   ```

3. Paste into the fixture file, redacting anything user-identifying (usernames,
   emails) with representative placeholder values.

## Current fixtures

| File                           | Endpoint                      | Notes                            |
| ------------------------------ | ----------------------------- | -------------------------------- |
| `session.json`                 | `GET /api/session`            | Regular logged-in user           |
| `session_admin.json`           | `GET /api/session`            | User with `admin:all` permission |
| `session_unauthenticated.json` | `GET /api/session` (401 body) | Logged-out response              |
