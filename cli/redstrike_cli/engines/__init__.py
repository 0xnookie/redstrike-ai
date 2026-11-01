"""Engine adapters — the seam that lets `redstrike` drive an engine other than Claude Code.

WHY THIS EXISTS
---------------
The launcher drives the native `claude` binary (see ``launch.py`` / ``autorun.py``). The
*methodology* is already engine-neutral — skills are markdown + JSON schemas under ``skills/``,
and the scope record / finding schemas / RoE are plain files on disk. What is Claude-Code-specific
is the **plumbing**:

  * the agent loop itself (Claude Code supplies it; an API-only model has none),
  * how the system prompt / skills are injected (``--append-system-prompt-file`` / ``--add-dir``),
  * how tool calls are GATED — the PreToolUse scope-gate hook in ``runtime/settings.json``,
  * how sub-agents (the independent reviewers) are spawned,
  * turn / budget caps and MCP isolation.

An ``Engine`` is the adapter that maps those engine-neutral artifacts onto one concrete engine.
``ClaudeCodeEngine`` is the adapter that exists today, now named and made explicit and wired into
``__main__`` (``redstrike run`` / ``doctor`` resolve an engine via ``get_engine`` and call it);
``CodexEngine`` / ``AgentSDKEngine`` are skeletons describing exactly what a second engine must
implement.

THE LOAD-BEARING SAFETY INVARIANT
---------------------------------
The scope gate is Redstrike's real in-session safety boundary (defense layer 2, over the OS
sandbox). **An engine MUST NOT be registered as usable until its ``gate``/tool-call equivalent
is as fail-closed as the Claude Code path** — it denies out-of-scope asset access and blocks
writes to the launcher-owned governance files, and fails CLOSED when the scope record is missing.
If an engine has no tool-gating hook at all, it cannot provide layer 2 and must not be offered for
live targets. ``Engine.supports_tool_gating`` advertises this; ``get_engine`` refuses to hand back
an engine that reports ``False`` unless the caller explicitly opts out (``allow_ungated=True``,
lab/offline only).

Only ``ClaudeCodeEngine`` is implemented; the others raise ``NotImplementedError`` when used.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


# --- shared, engine-neutral types ------------------------------------------
@dataclass
class RunResult:
    """Outcome of an engine run."""
    rc: int
    summary: str = ""


@dataclass
class Invocation:
    """A built, not-yet-executed engine invocation.

    ``argv`` is the exact command the engine will run (printed verbatim on ``--dry-run`` and
    handed to ``run``). ``allowed`` is the autonomous tool-allowlist, exposed so the CLI can show
    it on a dry run; it is ``None`` for interactive runs.
    """
    argv: list[str]
    allowed: list[str] | None = None
    meta: dict = field(default_factory=dict)


class PreparedRuntime(Protocol):
    """The engine-neutral view the launcher needs from a prepared engagement.

    ``launch.Prepared`` already satisfies this shape; a non-Claude engine returns its own object
    exposing at least these fields (plus whatever that engine's invocation needs).
    """
    engagement_id: str
    session_id: str
    scope: dict


# --- the adapter contract ---------------------------------------------------
class Engine(abc.ABC):
    """One offensive-engine backend. Subclasses own the engine-specific plumbing; the engagement
    dir, scope record, RoE and finding schemas stay engine-neutral.

    Lifecycle used by ``redstrike run`` (see ``__main__.cmd_run`` / ``_run_autonomous``):

        eng = get_engine(args.engine)
        prep = eng.prepare(eng_dir, repo, py, mode=...)   # materialize runtime/ for THIS engine
        if eng.gate(prep): abort                          # fail-closed scope/window check (shared)
        inv = eng.build_invocation(prep, repo, prompt, mode=..., ...)
        if dry_run or not eng.is_available(): print(eng.runtime_artifacts(prep, repo), inv.argv)
        elif eng.auth_status()[0] is not False: eng.run(prep, eng_dir, inv, mode=...)
    """

    #: stable short id, e.g. "claude-code", "codex", "agent-sdk".
    name: str = "engine"

    #: True only when this engine can gate tool calls in-session (fail-closed). See the module
    #: docstring — an engine without this cannot provide defense layer 2.
    supports_tool_gating: bool = False

    #: True when this engine can spawn the independent-reviewer sub-agents.
    supports_subagents: bool = False

    # -- discovery / health -------------------------------------------------
    @abc.abstractmethod
    def preflight(self, repo: Path) -> list:
        """Preflight checks (engine binary present, authenticated, platform sane), shape mirroring
        ``preflight.gather`` so ``redstrike doctor`` can render them."""

    @abc.abstractmethod
    def is_available(self) -> bool:
        """True when the engine runtime is present (e.g. its binary on ``PATH``). When False,
        ``redstrike run`` prints the planned invocation instead of launching."""

    @abc.abstractmethod
    def auth_status(self) -> tuple:
        """``(authed, detail)`` — ``authed`` is True/False/None (None == unknown/uncheckable)."""

    # -- runtime prep + gate (engine-neutral; delegate to shared modules) ---
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
        scope.json, render the governance config IN THIS ENGINE'S FORMAT (for Claude Code that is
        ``settings.json`` with the PreToolUse hook; another engine renders its own tool-permission
        config), the appended RoE, MCP/connector isolation, and a session id."""

    @abc.abstractmethod
    def gate(self, prep: PreparedRuntime) -> list[str]:
        """Pre-launch fail-closed check: scope completeness + engagement window open. Returns a
        list of blocking reasons (empty == clear). Engine-neutral — SHOULD delegate to
        ``scope``/``launch.gate`` so every engine enforces the same pre-launch rule."""

    @abc.abstractmethod
    def runtime_artifacts(self, prep: PreparedRuntime, repo: Path) -> list[tuple[str, str]]:
        """``(label, value)`` pairs describing the generated runtime for a dry run — e.g. the
        scope/settings/RoE paths (repo-relative) and the session id."""

    # -- build + run --------------------------------------------------------
    @abc.abstractmethod
    def build_invocation(
        self,
        prep: PreparedRuntime,
        repo: Path,
        prompt: str,
        *,
        mode: str = "interactive",
        permission_mode: str = "default",
        allow: list[str] | None = None,
        max_turns: int = 200,
        max_budget: float = 20.0,
        resume: bool = False,
    ) -> Invocation:
        """Build (but do not run) the engine invocation for ``mode`` in {interactive, autonomous}."""

    @abc.abstractmethod
    def run(
        self,
        prep: PreparedRuntime,
        eng_dir: Path,
        inv: Invocation,
        *,
        mode: str = "interactive",
        audit: Path | None = None,
    ) -> RunResult:
        """Execute ``inv``. Interactive attaches to the terminal (human-gated); autonomous runs
        headless, deny-by-default, teeing an audit trail to ``audit`` — any tool call the operator
        hasn't pre-allowed DEFERS (pause for approval) rather than running."""

    # -- convenience wrappers (in terms of the primitives) ------------------
    def run_interactive(self, prep, repo: Path, prompt: str, permission_mode: str = "default") -> int:
        inv = self.build_invocation(prep, repo, prompt, mode="interactive", permission_mode=permission_mode)
        eng_dir = Path(repo) / "engagements" / prep.engagement_id
        return self.run(prep, eng_dir, inv, mode="interactive").rc

    def run_autonomous(
        self, prep, repo: Path, prompt: str, *, allow, max_turns, max_budget, resume, audit
    ) -> RunResult:
        inv = self.build_invocation(
            prep, repo, prompt, mode="autonomous", allow=allow,
            max_turns=max_turns, max_budget=max_budget, resume=resume,
        )
        eng_dir = Path(repo) / "engagements" / prep.engagement_id
        return self.run(prep, eng_dir, inv, mode="autonomous", audit=audit)


# --- the engine that exists today, named -----------------------------------
class ClaudeCodeEngine(Engine):
    """Adapter over the native ``claude`` binary — today's behavior, factored behind the seam.

    It delegates to the existing modules so there is ONE implementation of the plumbing:
      * ``launch.prepare_runtime`` / ``launch.gate`` / ``launch.build_argv`` / ``launch.exec_claude``
      * ``launch.build_autonomous_argv`` + ``autorun.run_autonomous`` (stream + audit + defer)
      * ``preflight`` for the binary/auth checks, ``settings.autonomous_allowlist`` for the allowlist.

    Claude Code provides the agent loop, ``--add-dir`` skill loading, the PreToolUse scope-gate hook
    (layer 2), the ``Agent`` tool for reviewer sub-agents, ``--max-turns`` / ``--max-budget-usd`` and
    ``--strict-mcp-config`` — so both capability flags are True.
    """

    name = "claude-code"
    supports_tool_gating = True
    supports_subagents = True

    def _bin(self) -> str:
        from .. import preflight
        return preflight.find_claude() or "claude"

    def preflight(self, repo):
        from .. import preflight
        return preflight.gather(repo)

    def is_available(self) -> bool:
        from .. import preflight
        return preflight.find_claude() is not None

    def auth_status(self) -> tuple:
        from .. import preflight
        cb = preflight.find_claude()
        if not cb:
            return (None, "claude not on PATH")
        return preflight.claude_auth(cb)

    def prepare(self, engagement_dir, repo, python_exe, *, mode="interactive", extra_allow=None):
        from .. import launch
        return launch.prepare_runtime(
            engagement_dir, repo, python_exe, mode=mode, extra_allow=extra_allow
        )

    def gate(self, prep) -> list[str]:
        from .. import launch
        return launch.gate(prep)  # scope completeness + window (fail-closed)

    def runtime_artifacts(self, prep, repo) -> list[tuple[str, str]]:
        repo = Path(repo)

        def rel(p) -> str:
            try:
                return str(Path(p).relative_to(repo))
            except ValueError:
                return str(p)

        return [
            ("scope.json", rel(prep.scope_json)),
            ("settings", rel(prep.settings_path)),
            ("roe", rel(prep.roe_path)),
            ("session", prep.session_id),
        ]

    def build_invocation(self, prep, repo, prompt, *, mode="interactive", permission_mode="default",
                         allow=None, max_turns=200, max_budget=20.0, resume=False) -> Invocation:
        from .. import launch, settings as settingsmod
        cb = self._bin()
        if mode == "autonomous":
            allowed = settingsmod.autonomous_allowlist(allow or [])
            argv = launch.build_autonomous_argv(
                cb, repo, prep, prompt, allowed,
                max_turns=max_turns, max_budget=max_budget, resume=resume,
            )
            return Invocation(argv=argv, allowed=allowed)
        argv = launch.build_argv(cb, repo, prep, prompt, permission_mode)
        return Invocation(argv=argv, allowed=None)

    def run(self, prep, eng_dir, inv, *, mode="interactive", audit=None) -> RunResult:
        from .. import autorun, launch
        eng_dir = Path(eng_dir)
        if mode == "autonomous":
            if audit is None:
                audit = eng_dir / "runtime" / "autorun.jsonl"
            rc, summary = autorun.run_autonomous(
                self._bin(), inv.argv, eng_dir, audit, pending_path=prep.pending_path  # type: ignore[attr-defined]
            )
            return RunResult(rc=rc, summary=summary)
        rc = launch.exec_claude(inv.argv, cwd=eng_dir)
        return RunResult(rc=rc)


# --- skeletons: what a second engine must implement -------------------------
class _UnimplementedEngine(Engine):
    """Shared base for not-yet-built adapters: safe to import, explodes only when used."""

    def _nope(self, what: str):
        raise NotImplementedError(
            f"{self.name}: {what} is not implemented yet. See cli/ENGINES.md — and note the safety "
            f"invariant: do not enable this engine for live targets until its tool-gating equivalent "
            f"is fail-closed at parity with the Claude Code scope gate."
        )

    def preflight(self, repo):               return self._nope("preflight")
    def is_available(self) -> bool:          return False
    def auth_status(self) -> tuple:          return (None, f"{self.name} not implemented")
    def prepare(self, *a, **k):              return self._nope("prepare")
    def gate(self, prep):                    return self._nope("gate")
    def runtime_artifacts(self, prep, repo): return self._nope("runtime_artifacts")
    def build_invocation(self, *a, **k):     return self._nope("build_invocation")
    def run(self, *a, **k):                  return self._nope("run")


class CodexEngine(_UnimplementedEngine):
    """OpenAI Codex CLI adapter (skeleton).

    Plausible because Codex reads an ``AGENTS.md`` guide file and has approval modes, so the RoE and
    skills can be projected into its world. What differs and must be built:
      * prepare(): write ``AGENTS.md`` from the RoE + a Codex-shaped tool-permission policy instead
        of Claude Code's ``settings.json`` hook; isolate it from any ambient config.
      * gating parity: Codex's approval/sandbox policy must deny out-of-scope assets and
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
    can be the STRONGEST gating of the three. The work is the loop, tool wiring, the sub-agent
    spawner for reviewers, and turn/budget accounting. PLAN.md already names the Agent SDK the
    escape hatch for autonomous / in-process approval UI.
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


def register(cls: type[Engine]) -> type[Engine]:
    """Register an engine class by its ``name`` (handy for tests / out-of-tree adapters)."""
    _REGISTRY[cls.name] = cls
    return cls


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

    Refuses an engine whose in-session tool gating isn't fail-closed unless ``allow_ungated`` is
    set — guarding the safety invariant in the module docstring.
    """
    import os
    key = name or os.environ.get("REDSTRIKE_ENGINE") or DEFAULT_ENGINE
    cls = _REGISTRY.get(key)
    if cls is None:
        raise KeyError(f"unknown engine '{key}' (known: {', '.join(sorted(_REGISTRY))})")
    eng = cls()
    if not eng.supports_tool_gating and not allow_ungated:
        raise RuntimeError(
            f"engine '{key}' cannot gate tool calls fail-closed yet — refusing to run it against a "
            f"live target. Set REDSTRIKE_ENGINE / --engine only to an available engine "
            f"({', '.join(available()) or 'none'}); lab/offline callers may pass allow_ungated=True. "
            f"See cli/ENGINES.md."
        )
    return eng


__all__ = [
    "Engine", "ClaudeCodeEngine", "CodexEngine", "AgentSDKEngine",
    "RunResult", "Invocation", "PreparedRuntime",
    "get_engine", "available", "register", "DEFAULT_ENGINE",
]
