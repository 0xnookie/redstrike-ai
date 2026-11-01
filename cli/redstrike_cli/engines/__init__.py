"""Engine adapters — the seam that lets `redstrike` drive an engine other than Claude Code.

WHY THIS EXISTS
---------------
Today the launcher is hardwired to the native `claude` binary (see ``launch.py`` /
``autorun.py``). The *methodology* is already engine-neutral — skills are markdown +
JSON schemas under ``skills/``, and the scope record / finding schemas / RoE are plain
files on disk. What is Claude-Code-specific is the **plumbing**:

  * the agent loop itself (Claude Code supplies it; an API-only model has none),
  * how the system prompt / skills are injected (``--append-system-prompt-file`` / ``--add-dir``),
  * how tool calls are GATED — the PreToolUse scope-gate hook in ``runtime/settings.json``,
  * how sub-agents (the independent reviewers) are spawned,
  * turn / budget caps and MCP isolation.

An ``Engine`` is the adapter that maps those engine-neutral artifacts onto one concrete
engine. ``ClaudeCodeEngine`` is the adapter that exists today, now named and made explicit;
``CodexEngine`` / ``AgentSDKEngine`` are skeletons describing exactly what a second engine
must implement.

THE LOAD-BEARING SAFETY INVARIANT
---------------------------------
The scope gate is Redstrike's real in-session safety boundary (defense layer 2, over the OS
sandbox). **An engine MUST NOT be registered as usable until its ``gate_tool_call`` equivalent
is as fail-closed as the Claude Code path** — i.e. it denies out-of-scope asset access and
blocks writes to the launcher-owned governance files, and fails CLOSED when the scope record
is missing. If an engine has no tool-gating hook at all, it cannot provide layer 2 and must
not be offered for live targets. ``Engine.supports_tool_gating`` advertises this; the registry
refuses to hand back an engine that reports ``False`` unless the caller explicitly opts out.

This module is a SKETCH: importing it has no side effects and changes no current behavior.
Only ``ClaudeCodeEngine`` is implemented; the others raise ``NotImplementedError`` when used.
Nothing here is wired into ``__main__`` yet — see ``cli/ENGINES.md`` for the wiring plan.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


# --- shared, engine-neutral result types -----------------------------------
@dataclass
class RunResult:
    """Outcome of an engine run."""
    rc: int
    summary: str = ""


class PreparedRuntime(Protocol):
    """The engine-neutral view the launcher needs from a prepared engagement.

    ``launch.Prepared`` already satisfies this shape; a non-Claude engine returns its own
    object exposing at least these fields (plus whatever that engine's invocation needs).
    """
    engagement_id: str
    session_id: str
    scope: dict


# --- the adapter contract ---------------------------------------------------
class Engine(abc.ABC):
    """One offensive-engine backend. Subclasses own the engine-specific plumbing;
    the engagement dir, scope record, RoE and finding schemas stay engine-neutral.

    Lifecycle used by ``redstrike run``:

        eng = get_engine()                         # pick the backend
        for c in eng.preflight(repo): ...          # binary present + authenticated?
        prep = eng.prepare(eng_dir, repo, py, ...) # materialize runtime/ for THIS engine
        if eng.gate(prep): abort                   # fail-closed scope/window check (shared)
        rc = eng.run_interactive(prep, repo, ...)  # or eng.run_autonomous(...)
    """

    #: stable short id, e.g. "claude-code", "codex", "agent-sdk".
    name: str = "engine"

    #: True only when this engine can gate tool calls in-session (fail-closed). See the
    #: module docstring — an engine without this cannot provide defense layer 2.
    supports_tool_gating: bool = False

    #: True when this engine can spawn the independent-reviewer sub-agents in-process.
    supports_subagents: bool = False

    @abc.abstractmethod
    def preflight(self, repo: Path) -> list:
        """Return a list of preflight checks (engine binary present, authenticated, platform
        sane). Shape mirrors ``preflight.gather`` so ``redstrike doctor`` can render them."""

    @abc.abstractmethod
    def prepare(
        self,
        engagement_dir: Path,
        repo: Path,
        python_exe: str,
        *,
        mode: str = "interactive",
        extra_allow: list[str] | None = None,
    ) -> PreparedRuntime:
        """Materialize this engine's ``runtime/`` for the engagement: project scope.yaml ->
        scope.json, render the governance config IN THIS ENGINE'S FORMAT (for Claude Code that
        is ``settings.json`` with the PreToolUse hook; another engine renders its own tool-
        permission config), the appended RoE, MCP/connector isolation, and a session id."""

    @abc.abstractmethod
    def gate(self, prep: PreparedRuntime) -> list[str]:
        """Pre-launch fail-closed check: scope completeness + engagement window open. Returns
        a list of blocking reasons (empty == clear). This is engine-neutral and SHOULD delegate
        to ``scope``/``launch.gate`` so every engine enforces the same pre-launch rule."""

    @abc.abstractmethod
    def run_interactive(
        self, prep: PreparedRuntime, repo: Path, prompt: str, permission_mode: str = "default"
    ) -> int:
        """Launch the engine attached to the operator's terminal, human-gated. Returns an rc."""

    @abc.abstractmethod
    def run_autonomous(
        self,
        prep: PreparedRuntime,
        repo: Path,
        prompt: str,
        *,
        allow: list[str],
        max_turns: int,
        max_budget: float,
        resume: bool,
        audit: Path,
    ) -> RunResult:
        """Run headless/unattended, deny-by-default, bounded by turns + budget, teeing an audit
        trail to ``audit``. Any tool call the operator has not pre-allowed must DEFER (pause for
        approval), not run — the defer -> approve -> resume loop (``approvals`` module)."""


# --- the engine that exists today, named -----------------------------------
class ClaudeCodeEngine(Engine):
    """Adapter over the native ``claude`` binary — today's behavior, factored behind the seam.

    It delegates to the existing modules so there is ONE implementation of the plumbing:
      * ``launch.prepare_runtime`` / ``launch.gate`` / ``launch.build_argv`` / ``launch.exec_claude``
      * ``launch.build_autonomous_argv`` + ``autorun.run_autonomous`` (stream + audit + defer)
      * ``preflight`` for the binary/auth checks.

    Claude Code provides the agent loop, ``--add-dir`` skill loading, the PreToolUse scope-gate
    hook (layer 2), the ``Agent`` tool for reviewer sub-agents, ``--max-turns`` / ``--max-budget-usd``
    and ``--strict-mcp-config`` — so both capability flags are True.
    """

    name = "claude-code"
    supports_tool_gating = True
    supports_subagents = True

    def preflight(self, repo: Path) -> list:
        from .. import preflight
        return preflight.gather(repo)

    def prepare(self, engagement_dir, repo, python_exe, *, mode="interactive", extra_allow=None):
        from .. import launch
        return launch.prepare_runtime(
            engagement_dir, repo, python_exe, mode=mode, extra_allow=extra_allow
        )

    def gate(self, prep) -> list[str]:
        from .. import launch
        return launch.gate(prep)  # scope completeness + window (fail-closed)

    def run_interactive(self, prep, repo, prompt, permission_mode="default") -> int:
        from .. import launch, preflight
        claude_bin = preflight.find_claude() or "claude"
        argv = launch.build_argv(claude_bin, repo, prep, prompt, permission_mode)
        return launch.exec_claude(argv, cwd=Path(repo) / "engagements" / prep.engagement_id)

    def run_autonomous(self, prep, repo, prompt, *, allow, max_turns, max_budget, resume, audit) -> RunResult:
        from .. import autorun, launch, preflight, settings as settingsmod
        claude_bin = preflight.find_claude() or "claude"
        allowed = settingsmod.autonomous_allowlist(allow)
        argv = launch.build_autonomous_argv(
            claude_bin, repo, prep, prompt, allowed,
            max_turns=max_turns, max_budget=max_budget, resume=resume,
        )
        eng_dir = Path(repo) / "engagements" / prep.engagement_id
        rc, summary = autorun.run_autonomous(
            claude_bin, argv, eng_dir, audit, pending_path=prep.pending_path  # type: ignore[attr-defined]
        )
        return RunResult(rc=rc, summary=summary)


# --- skeletons: what a second engine must implement -------------------------
class _UnimplementedEngine(Engine):
    """Shared base for not-yet-built adapters: safe to import, explodes only when used."""

    def _nope(self, what: str):
        raise NotImplementedError(
            f"{self.name}: {what} is not implemented yet. See cli/ENGINES.md — and note the "
            f"safety invariant: do not enable this engine for live targets until its tool-gating "
            f"equivalent is fail-closed at parity with the Claude Code scope gate."
        )

    def preflight(self, repo):            return self._nope("preflight")
    def prepare(self, *a, **k):           return self._nope("prepare")
    def gate(self, prep):                 return self._nope("gate")
    def run_interactive(self, *a, **k):   return self._nope("run_interactive")
    def run_autonomous(self, *a, **k):    return self._nope("run_autonomous")


class CodexEngine(_UnimplementedEngine):
    """OpenAI Codex CLI adapter (skeleton).

    Plausible because Codex reads an ``AGENTS.md`` guide file and has approval modes, so the RoE
    and skills can be projected into its world. What differs and must be built:
      * prepare(): write ``AGENTS.md`` from the RoE + a Codex-shaped tool-permission policy
        instead of Claude Code's ``settings.json`` hook; isolate it from any ambient config.
      * gate_tool_call parity: Codex's approval/sandbox policy must deny out-of-scope assets and
        governance-file writes and FAIL CLOSED — otherwise ``supports_tool_gating`` stays False.
      * subagents: map the independent-reviewer pattern onto Codex sub-invocations.
    Flip the capability flags to True only once those hold.
    """
    name = "codex"
    supports_tool_gating = False   # until the sandbox/approval policy reaches fail-closed parity
    supports_subagents = False


class AgentSDKEngine(_UnimplementedEngine):
    """Claude Agent SDK / own-loop adapter (skeleton), for API-key-billed or in-process runs.

    Here Redstrike owns the agent loop, so the scope gate becomes an in-process tool-call
    interceptor (reuse ``hooks/scope_gate`` logic directly) rather than a PreToolUse hook — which
    can actually be the STRONGEST gating of the three. The work is the loop, tool wiring, the
    sub-agent spawner for reviewers, and turn/budget accounting. PLAN.md already named the Agent
    SDK the escape hatch for autonomous / in-process approval UI.
    """
    name = "agent-sdk"
    supports_tool_gating = False   # True once the in-process interceptor is wired + fail-closed
    supports_subagents = False


# --- registry ---------------------------------------------------------------
_REGISTRY: dict[str, type[Engine]] = {
    ClaudeCodeEngine.name: ClaudeCodeEngine,
    CodexEngine.name: CodexEngine,
    AgentSDKEngine.name: AgentSDKEngine,
}

DEFAULT_ENGINE = ClaudeCodeEngine.name


def available() -> list[str]:
    """Engine ids that are safe to run live now (implemented AND fail-closed gating)."""
    out = []
    for name, cls in _REGISTRY.items():
        try:
            if cls().supports_tool_gating:
                out.append(name)
        except Exception:
            pass
    return out


def get_engine(name: str | None = None, *, allow_ungated: bool = False) -> Engine:
    """Resolve an engine by id (default: ``$REDSTRIKE_ENGINE`` or ``claude-code``).

    Refuses an engine whose in-session tool gating isn't fail-closed unless ``allow_ungated``
    is set — guarding the safety invariant in the module docstring.
    """
    import os
    key = name or os.environ.get("REDSTRIKE_ENGINE") or DEFAULT_ENGINE
    cls = _REGISTRY.get(key)
    if cls is None:
        raise KeyError(f"unknown engine '{key}' (known: {', '.join(sorted(_REGISTRY))})")
    eng = cls()
    if not eng.supports_tool_gating and not allow_ungated:
        raise RuntimeError(
            f"engine '{key}' cannot gate tool calls fail-closed yet — refusing to run it against "
            f"a live target. Pass allow_ungated=True only for offline/lab use. See cli/ENGINES.md."
        )
    return eng


__all__ = [
    "Engine", "ClaudeCodeEngine", "CodexEngine", "AgentSDKEngine",
    "RunResult", "PreparedRuntime",
    "get_engine", "available", "DEFAULT_ENGINE",
]
