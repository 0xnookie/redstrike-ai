# `redstrike` CLI

A thin launcher that runs **Claude Code as the engagement engine**. The user runs
`redstrike` instead of `claude`; the launcher bootstraps an engagement (authorization
+ scope), enforces a scope/RoE gate, and starts Claude Code preloaded with the repo's
`.claude/` skills + subagents. Interactive and human-gated by default.

Unlike a self-contained agent framework, this does **not** reimplement an agent loop —
Claude Code stays the engine; the CLI is governance + orchestration glue. Everything
coordinates through files in the engagement directory, so a run can be bootstrapped,
gated, and resumed by reading/writing that directory.

## Status
`v0.1.0` — **interactive, gated** (M0–M3). Autonomous headless (`-p`) is a later milestone;
see `PLAN.md`.

## Install
```bash
pipx install ./cli            # provides `redstrike`; requires `claude` on PATH
# or, from a clone, run without installing:
PYTHONPATH=cli python -m redstrike_cli --help
```
Stdlib-only (PyYAML used if present, else a bundled reader). Engagements run on **WSL2/Linux**
(the OS sandbox the scope gate leans on is Linux-only; native Windows has no sandbox).

## Quickstart
```bash
redstrike doctor                       # engine + auth + platform + tool roster preflight
redstrike init "Acme Corp" \           # scaffold engagements/acme-corp-<date>/ + scope.yaml
  --authorized-by "sec@acme / auth-ref" \
  --domain '*.acme.com' --domain api.acme.com \
  --exclude-domain admin.acme.com \
  --i-confirm-authorization            # assert written authorization is on file
# review the generated scope.yaml, then:
redstrike run acme-corp-<date>         # launch Claude Code, scoped + gated (interactive)
redstrike run acme-corp-<date> --dry-run   # inspect the exact argv + generated runtime/ files
redstrike status acme-corp-<date>      # findings-by-severity/status + scope summary
redstrike verify acme-corp-<date>      # run the deterministic gate (verify_completion.py)
```

## How it works
`redstrike run` materializes a per-engagement `runtime/` and execs:
```
claude "<begin prompt>" --add-dir <repo> --append-system-prompt-file runtime/roe.md \
  --settings runtime/settings.json --setting-sources project,local \
  --permission-mode default --session-id <uuid> -n <engagement>
```
- **`--add-dir <repo>`** loads the repo's `.claude/skills` + `.claude/agents`.
- **`runtime/roe.md`** (appended system prompt) states the scope + RoE and that authorization
  intake is already satisfied, so a launched session doesn't stall re-asking for a go-ahead.
- **`runtime/settings.json`** carries the governance: a **PreToolUse scope-gate hook**, denies
  that keep the agent out of the launcher-owned governance files, a modest read-only tool
  allowlist, and subagent/memory bounds. Offensive tools are **not** pre-approved.
- **`runtime/scope.json`** is a machine projection of the canonical, signed `scope.yaml`
  (re-derived on every run). The scope gate reads the JSON; the operator edits the YAML.

## Safety model (and honest limits)
- The scope gate (`hooks/scope_gate.py`) **denies** tool calls that reach an out-of-scope asset
  (WebFetch / active Bash), and blocks writes to `runtime/` and `scope.yaml` (self-approval guard).
  It **fails closed** when the scope record is missing.
- A hook matching tool *input* is a **safety net, not a boundary** — the real network boundary is
  the OS sandbox allowlist (`settings.sandbox.network`) on WSL2/Linux. Bash permission rules are
  pattern-based, not a boundary either.
- **Native Windows has no OS sandbox** — run engagements in WSL2/Linux.
- **Auth:** personal use via `claude login` (subscription) or `CLAUDE_CODE_OAUTH_TOKEN`.
  `ANTHROPIC_API_KEY`, if set, overrides and bills the key. A product distributed to others must
  use API keys per Anthropic's terms.

## Development
```bash
# run the unit tests (stdlib unittest)
for t in cli/tests/test_*.py; do python "$t"; done
```
