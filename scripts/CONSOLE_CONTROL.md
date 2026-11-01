# Console control plane (experimental)

`scripts/console.py` is a **read-only** viewer. `scripts/console_control.py` is an **opt-in**
backend that lets the console *launch and steer* an engagement, closing the "viewer vs. doer"
gap. It is a **scaffold**: the endpoints are real, but the `console/` Next.js frontend is not yet
wired to call them, and only autonomous runs are supported (a web server has no TTY for an
interactive Claude Code session).

## Why it's locked down

A read-only viewer is low-risk. An endpoint that launches offensive tooling is a browser-reachable
path to running a pentest — so the plane:

- **refuses to start without `--enable-control`** (never the default),
- binds **`127.0.0.1` only**,
- requires a **bearer token** (`Authorization: Bearer <token>`) on every `/api/*` route — a
  *header*, not a cookie, so a cross-site page can't be CSRF'd into sending it,
- rejects non-localhost `Host` (anti DNS-rebinding) and cross-origin requests, and sends no
  permissive CORS headers,
- **shells out to the same `redstrike` CLI** the terminal uses, so the scope gate, the fail-closed
  launch gate, the deny-by-default allowlist and the audit trail are all enforced by the launcher —
  nothing is re-implemented or bypassed here. A launched run still defers every un-allowlisted
  command for approval.

## Run

```sh
python scripts/console_control.py --enable-control                  # all engagements/
python scripts/console_control.py --enable-control engagements/<id> # one engagement
REDSTRIKE_CONSOLE_TOKEN=mysecret python scripts/console_control.py --enable-control
```

Prints the URL (`127.0.0.1:8788` by default) and the token. For unattended Claude auth, export
`CLAUDE_CODE_OAUTH_TOKEN` before starting (inherited by launched runs).

## Endpoints (all require the bearer token)

| Method | Route | Maps to |
|---|---|---|
| GET | `/api/status` | discovered engagements + live run pids |
| POST | `/api/engagements` | `redstrike init` — body `{client, domains[], authorized_by, confirm_authorization:true, cidrs?[], window_days?}` |
| POST | `/api/engagements/<id>/run` | `redstrike run <id> --autonomous` — body `{allow?[], max_turns?, max_budget?, resume?}` |
| GET | `/api/engagements/<id>/stream` | SSE tail of `runtime/autorun.jsonl` |
| GET | `/api/engagements/<id>/approvals` | `runtime/approvals_pending.json` |
| POST | `/api/engagements/<id>/approve` | `redstrike approve <id>` — body `{ids[]}` or `{all:true}` |
| POST | `/api/engagements/<id>/stop` | SIGTERM the tracked run's process group |

`confirm_authorization:true` carries the same meaning as the CLI's `--i-confirm-authorization`:
you are asserting written authorization for the scope is on file.

Example:

```sh
T=<token>
curl -s -H "Authorization: Bearer $T" http://127.0.0.1:8788/api/status
curl -s -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d '{"allow":["Bash(nmap *)"],"max_turns":100}' \
  http://127.0.0.1:8788/api/engagements/acme-corp-2026-11-01/run
curl -sN -H "Authorization: Bearer $T" \
  http://127.0.0.1:8788/api/engagements/acme-corp-2026-11-01/stream
```

## Not done yet (scaffold boundaries)

- Frontend: `console/` doesn't call these routes — needs a launch form, a live run view (consume
  the SSE), and an approvals panel wired to `/approve` + `/run …?resume`.
- Interactive runs: unsupported over HTTP (no TTY) — autonomous only.
- `init` validation is minimal (delegates to the CLI); no scope-editing UI.
- Multi-user/remote: out of scope by design — localhost + single token only. Do not expose this
  beyond the loopback interface.
