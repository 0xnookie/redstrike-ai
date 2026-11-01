# Engine adapters — driving Redstrike with an engine other than Claude Code

**Status: design sketch.** `redstrike_cli/engines/__init__.py` defines the seam and names
today's Claude Code engine; the other adapters are skeletons. Nothing here is wired into
`__main__.py` yet, so current behavior is unchanged. This doc is the plan to finish it.

## Why

The launcher is hardwired to the native `claude` binary (`launch.py` / `autorun.py`). But the
**methodology is already engine-neutral** — skills are markdown + JSON schemas under `skills/`,
and the scope record, finding schemas and RoE are plain files on disk. What is tied to Claude
Code is the *plumbing*:

| Concern | Claude Code mechanism | Engine-neutral? |
|---|---|---|
| Agent loop | provided by `claude` | ❌ engine-specific |
| System prompt / RoE injection | `--append-system-prompt-file runtime/roe.md` | RoE text ✅ / injection ❌ |
| Skill + subagent loading | `--add-dir <repo>` (`.claude/skills`, `.claude/agents`) | content ✅ / loading ❌ |
| **In-session tool gating** | PreToolUse **scope-gate hook** in `runtime/settings.json` | gate *logic* ✅ / wiring ❌ |
| Reviewer sub-agents | the `Agent` tool | pattern ✅ / spawn ❌ |
| Isolation | `--strict-mcp-config --mcp-config runtime/mcp-none.json` | ❌ engine-specific |
| Caps | `--max-turns` / `--max-budget-usd` | ❌ engine-specific |

An `Engine` adapter maps the neutral artifacts onto one concrete engine.

## The contract

```python
class Engine(ABC):
    name: str
    supports_tool_gating: bool   # fail-closed in-session gating — see invariant below
    supports_subagents: bool

    def preflight(repo) -> list[Check]
    def prepare(engagement_dir, repo, python_exe, *, mode, extra_allow) -> PreparedRuntime
    def gate(prep) -> list[str]                        # fail-closed scope/window (shared)
    def run_interactive(prep, repo, prompt, permission_mode) -> int
    def run_autonomous(prep, repo, prompt, *, allow, max_turns, max_budget, resume, audit) -> RunResult
```

`prepare()` is where the engine-specific config is rendered. For Claude Code that is
`runtime/settings.json` (hook + denies + bounds); another engine renders its own tool-permission
config from the *same* scope projection. Everything downstream of `prepare()` — the scope.yaml ->
scope.json projection, the RoE text, the finding schemas, the completion gate — stays shared.

### The load-bearing safety invariant

The scope gate is Redstrike's real in-session boundary (defense **layer 2**, over the OS sandbox
which is layer 3; the model's own RoE self-refusal is layer 1). Therefore:

> **An engine MUST NOT be offered for live targets until its `gate_tool_call` equivalent is
> fail-closed at parity with the Claude Code scope gate** — it denies out-of-scope asset access,
> blocks writes to the launcher-owned governance files (`runtime/`, `scope.yaml`), and fails
> CLOSED when the scope record is missing.

`supports_tool_gating` advertises this per engine. `get_engine()` refuses to return an engine that
reports `False` unless the caller passes `allow_ungated=True` (offline/lab only). An engine with no
tool-gating hook at all cannot provide layer 2 and leans entirely on the OS sandbox — do not point
it at a real target.

## Capability matrix

| Engine | id | gating | subagents | state |
|---|---|---|---|---|
| Claude Code (native `claude`) | `claude-code` | ✅ PreToolUse hook | ✅ `Agent` tool | **implemented** (factored from `launch.py`) |
| OpenAI Codex CLI | `codex` | ⬜ needs sandbox/approval parity | ⬜ | skeleton |
| Claude Agent SDK / own loop | `agent-sdk` | ⬜ in-process interceptor | ⬜ | skeleton |

## Per-engine work

**`codex`** — plausible: Codex reads `AGENTS.md` and has approval modes.
- `prepare()`: project the RoE into `AGENTS.md`; render a Codex-shaped tool-permission/sandbox
  policy from `scope.json` in place of `settings.json`.
- gating parity: Codex's approval/sandbox policy must deny out-of-scope + governance writes and
  fail closed. Until then `supports_tool_gating = False`.
- subagents: map the reviewer pattern onto Codex sub-invocations.

**`agent-sdk`** — Redstrike owns the loop, so the scope gate becomes an **in-process tool-call
interceptor** reusing `hooks/scope_gate` logic directly. This can be the *strongest* gating of the
three (no reliance on an external hook contract). Work: the loop, tool wiring, a sub-agent spawner
for reviewers, turn/budget accounting. `PLAN.md` already names the Agent SDK the escape hatch for
autonomous / in-process approval UI (M5+).

## Wiring plan (not done here)

1. `redstrike run` / `doctor` take `--engine <id>` (default `$REDSTRIKE_ENGINE` or `claude-code`)
   and call `engines.get_engine(...)` instead of calling `launch`/`preflight` directly.
2. `cmd_run` / `_run_autonomous` call `eng.prepare` / `eng.gate` / `eng.run_*` — the control flow
   is already shaped this way, so the diff is mechanical.
3. `doctor` renders `eng.preflight(repo)` and lists `engines.available()`.
4. Tests: a fake engine exercising the dispatch; the ClaudeCodeEngine path asserted equivalent to
   the current direct calls (no behavior change).

Keeping `get_engine()` fail-closed by default means adding an engine can't silently weaken a live
run — a half-built adapter refuses to launch rather than running ungated.
