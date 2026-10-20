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
`v0.1.0` — **interactive, gated**, plus an opt-in **autonomous headless** mode with a defer → approve →
resume loop (M0–M5.1). See `PLAN.md`.

## Install
One command — Linux (Kali/Ubuntu/Debian), macOS, or WSL. After it, **`redstrike` is a global command**
you run from anywhere (the repo path is baked into the launcher):
```bash
git clone https://github.com/0xnookie/redstrike-ai.git
cd redstrike-ai
./cli/install.sh          # installs `redstrike` to ~/.local/bin (needs python3 + its venv module)
redstrike doctor
```
Debian/Ubuntu/WSL: if it asks, `sudo apt install -y python3-venv` first. Add `~/.local/bin` to `PATH` if the
installer says so. Also needs the **`claude`** CLI (Claude Code) on `PATH` + `claude login`.

Alternatives: `pipx install ./cli`, or run in place without installing: `PYTHONPATH=cli python3 -m redstrike_cli --help`.

Stdlib-only (PyYAML used if present, else a bundled reader). Engagements run on **WSL2/Linux**
(the OS sandbox the scope gate leans on is Linux-only; native Windows has no sandbox).

## Quickstart
```bash
redstrike doctor                       # engine + auth + platform + tool roster preflight
redstrike install --core               # install the offensive tool roster (wraps scripts/install.sh; --all / cats)
redstrike init "Acme Corp" \           # scaffold engagements/acme-corp-<date>/ + scope.yaml
  --authorized-by "sec@acme / auth-ref" \
  --domain '*.acme.com' --domain api.acme.com \
  --exclude-domain admin.acme.com \
  --i-confirm-authorization            # assert written authorization is on file
# review the generated scope.yaml, then:
redstrike run acme-corp-<date>         # launch Claude Code, scoped + gated (interactive)
redstrike run acme-corp-<date> --console   # …then bring up the web console when the run finishes
redstrike run acme-corp-<date> --dry-run   # inspect the exact argv + generated runtime/ files
redstrike run acme-corp-<date> --autonomous --max-turns 200 --max-budget-usd 20 --allow 'Bash(nmap *)'
redstrike status acme-corp-<date>      # findings-by-severity/status + scope summary
redstrike verify acme-corp-<date>      # run the deterministic gate (verify_completion.py)
redstrike console                      # open the web console over ALL engagements (idempotent)
redstrike console acme-corp-<date>     # …or just one engagement
```

`--console` (or `REDSTRIKE_CONSOLE=1`) brings up the web console (`scripts/console.py`) when a
run finishes. It's **idempotent** — if a console is already serving the port it just opens the
browser instead of stacking a second server — and the console re-scans `engagements/` on every
request, so a scan that finished after launch shows up on refresh. `redstrike console` starts it
on demand (foreground; `--background` to detach, `--no-open` to skip the browser).

## Autonomous mode (`--autonomous`)
Runs headless via `claude -p` with a streamed progress view + run summary, **deny-by-default**
(`--permission-mode dontAsk`), bounded by `--max-turns` / `--max-budget-usd`, MCP-isolated
(`--strict-mcp-config`), with every event teed to `runtime/autorun.jsonl` as an audit trail.

Read-only recon (`Read`/`Grep`/`Glob`/`Skill`/`Agent`/`WebSearch`/`WebFetch`, in-scope) runs on its own.
**Shell is gated by the scope-gate hook**: a command you pre-allowed with `--allow` (e.g.
`--allow 'Bash(nmap *)'`, or broadly `--allow Bash`) runs; anything else is **deferred for your approval**
rather than run; out-of-scope is denied outright.

### Approve → resume loop
When a command is deferred the run pauses (`stop: tool_deferred`) and records it. Review, approve, resume —
the gate then lets the approved command run and the engagement continues (new un-approved actions defer again):

```bash
redstrike approve <eng> --list                # see pending deferrals (by fingerprint)
redstrike approve <eng>                        # interactive y/N per item  (or --all / --id <fp>)
redstrike run <eng> --autonomous --resume      # approved commands re-run; new ones defer again
```

Approvals and the pending queue live in `runtime/approvals.json` + `runtime/approvals_pending.json`
(launcher-owned; the agent is denied writing `runtime/`). For a fully unattended host, authenticate with a
long-lived token: `claude setup-token` → `export CLAUDE_CODE_OAUTH_TOKEN=…` (the launcher inherits it).

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
