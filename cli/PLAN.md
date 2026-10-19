# Build plan — `redstrike` CLI

A CLI the user runs instead of `claude`, which runs **Claude Code as the engagement
engine**, preloaded with the repo's skills/agents + a scope/RoE gate. v1 is interactive
and human-gated; autonomous headless (`-p`) is deferred.

## Design decisions (load-bearing)
- **Thin Python launcher over the native `claude` binary** — no new agent loop. The Agent
  SDK is the escape hatch for M5 (autonomous / in-process approval UI).
- **The CLI is stateless glue.** All state = the engagement dir + `--session-id`.
- **Governance lives in launcher-generated config, not methodology files** — the PreToolUse
  scope-gate hook, denies, allowlist and bounds are in a generated `runtime/settings.json`.
- **Scope record is launcher-owned, agent-read-only.** `scope.yaml` is the signed canonical
  record; `runtime/scope.json` is its machine projection; the agent is denied writing either.
- **WSL2/Linux runtime.** Native Windows has no OS sandbox.

## Component layout (`cli/`)
```
cli/
  pyproject.toml                 # [project.scripts] redstrike = redstrike_cli.__main__:main
  redstrike_cli/
    __main__.py                  # argparse: doctor | init | run | verify | status | version
    ui.py                        # REDSTRIKE banner + theme (zero-dep, UTF-8/ASCII aware)
    engagement.py                # scaffold engagements/<client>-<date>/ + scope.yaml + authz record
    yamlio.py                    # scope.yaml read (PyYAML or stdlib fallback) + render
    scope.py                     # scope.json projection, window/completeness checks, summary
    preflight.py                 # claude version/auth, python/node, platform/WSL, doctor.sh wrap
    settings.py                  # render runtime/settings.json (hook + denies + bounds)
    roe.py                       # render runtime/roe.md (appended system prompt)
    launch.py                    # build argv, prepare runtime, gate (fail-closed), exec claude
    gate.py                      # wrap verify_completion.py + findings status view
    hooks/scope_gate.py          # self-contained PreToolUse scope gate (stdlib)
  tests/                         # stdlib unittest (yaml, scope-gate, scope/settings/roe, CLI)
```

## Milestones
- [x] **M0 — Scaffolding + preflight.** `cli/` package + console script; `redstrike doctor`
      (claude/auth/platform + `doctor.sh`); `redstrike init` scaffolds the engagement + scope.yaml
      + an operator authorization record. `version`.
- [x] **M1 — Interactive launch.** `redstrike run` builds the argv, generates `runtime/{scope.json,
      settings.json,roe.md}`, gates on window+scope completeness (fail-closed), and execs `claude`
      (or prints the plan on `--dry-run`). Orchestrator §0 made non-interactive when launched by the CLI.
- [x] **M2 — Scope-gate hook.** `hooks/scope_gate.py` denies out-of-scope WebFetch/Bash and blocks
      writes to the governance files; fails closed on a missing scope record. Unit + stdin-level tested.
- [x] **M3 — Gate + status glue.** `redstrike verify` (consolidated + per-skill modes); `redstrike status`.
- [x] **M4 — Hardening + packaging.** pyproject + console script (pip-install verified; `redstrike`
      runs from the installed package); repo autodetect via cwd-walk with a clean error when run
      out-of-tree; version-floor assertion; UTF-8/ASCII-safe output; README + INSTALL.md WSL2 section;
      CI `cli` job runs the unit tests + packaging + a dry-run smoke on Python 3.10/3.11/3.12. Also
      validated on WSL2 (python 3.12 tests green; POSIX hook command + argv confirmed).
      **MCP isolation:** `run` now passes `--strict-mcp-config --mcp-config runtime/mcp-none.json`
      (a live probe showed the operator's claude.ai connectors otherwise leak into the session).

### Live verification (real `claude -p` on an authed host)
- Engine launches with our `--settings` + `--add-dir` + `--append-system-prompt-file`; the init event
  shows **all 102 redstrike skills loaded** and `mcp_servers: []` (isolated).
- RoE injection reaches the model: it echoed the engagement ID + in-scope domain, and self-refused an
  out-of-scope request (defense layer 1).
- The **scope-gate hook fires in-session** and blocks an out-of-scope Bash call before it runs, with our
  reason surfaced (defense layer 2). Minor polish: Claude labels the block a "hook error" line (it still
  blocks correctly) — could switch to exit-2 phrasing later.
- [ ] **M5 — Autonomous `-n` (deferred).** `-p` + stream-json event loop, `defer`-based approval with
      resume, budget/turn caps, OAuth-token auth, run summary. The launcher is structured to add this
      without rework.

## Branding / UI
The launcher owns its terminal, so it carries the REDSTRIKE identity on its own surfaces
(banner on `version`/`doctor`/`init`/`run`, panels, PASS/FAIL styling). Inside the interactive
Claude Code session the screen is Claude Code's TUI — reachable only via a statusline (a later
touch), not a full reskin. `ui.py` degrades to ASCII on a legacy console and honors `NO_COLOR`.

## Open items / notes
- `scope_gate.py` is a safety net over the OS sandbox, not a replacement for it (see README).
- Autonomous mode needs the non-interactive scope record (already written at `init`) plus a
  `defer`/resume loop and a responder — tracked under M5.
