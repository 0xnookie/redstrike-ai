"""Assemble runtime artifacts and launch (or dry-run) the Claude Code engine."""
from __future__ import annotations

import datetime as _dt
import json
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

from . import approvals as approvalsmod
from . import roe as roemod
from . import scope as scopemod
from . import settings as settingsmod


@dataclass
class Prepared:
    engagement_id: str
    scope_json: Path
    settings_path: Path
    roe_path: Path
    mcp_config: Path
    approvals_path: Path
    pending_path: Path
    session_id: str
    scope: dict


def default_prompt(engagement_id: str) -> str:
    return (
        f"Begin Redstrike engagement '{engagement_id}'. Authorization and scope are already "
        f"recorded in scope.yaml and the appended RoE — the orchestrator's §0 authorization "
        f"intake is SATISFIED, do not re-ask for a go-ahead. Invoke the redstrike orchestrator "
        f"skill and proceed through recon → gated vuln hunting → chaining → reporting, honoring "
        f"the active scope gate and the approval-gated phases."
    )


def hook_script() -> Path:
    """Absolute path to the real (self-contained) scope-gate script, wherever installed."""
    from .hooks import scope_gate

    return Path(scope_gate.__file__).resolve()


def prepare_runtime(
    engagement_dir: Path,
    repo_root: Path,
    python_exe: str,
    *,
    mode: str = "interactive",
    extra_allow: list[str] | None = None,
) -> Prepared:
    engagement_dir = engagement_dir.resolve()
    scope_yaml = engagement_dir / "scope.yaml"
    if not scope_yaml.is_file():
        raise FileNotFoundError(f"no scope.yaml in {engagement_dir} — run `redstrike init` first")

    runtime = engagement_dir / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    scope_json = runtime / "scope.json"
    proj = scopemod.derive_scope_json(scope_yaml, scope_json)  # re-derive from canonical YAML

    gate_policy = runtime / "gate-policy.json"
    approvals_path = runtime / "approvals.json"
    pending_path = runtime / "approvals_pending.json"
    if mode == "autonomous":
        gate_policy.write_text(
            json.dumps(
                {"mode": "autonomous", "bash_allow": settingsmod.bash_allow_globs(extra_allow)}, indent=2
            ) + "\n",
            encoding="utf-8",
        )
        approvalsmod.ensure_files(approvals_path, pending_path)  # keeps existing approvals

    settings_path = runtime / "settings.json"
    settings = settingsmod.render_settings(
        python_exe=python_exe, hook_script=hook_script(), scope_json=scope_json,
        mode=mode, extra_allow=extra_allow,
        gate_policy=(gate_policy if mode == "autonomous" else None),
        approvals=(approvals_path if mode == "autonomous" else None),
    )
    settingsmod.write_settings(settings_path, settings)

    engagement_id = engagement_dir.name
    roe_path = runtime / "roe.md"
    roe_path.write_text(
        roemod.render_roe(proj, engagement_id, autonomous=(mode == "autonomous")), encoding="utf-8"
    )

    # Empty MCP config + --strict-mcp-config isolates the engagement from the operator's
    # claude.ai connectors / plugin MCP servers (observed leaking in without it).
    mcp_config = runtime / "mcp-none.json"
    mcp_config.write_text(json.dumps({"mcpServers": {}}, indent=2) + "\n", encoding="utf-8")

    session_file = runtime / "session.json"
    if session_file.is_file():
        session_id = json.loads(session_file.read_text(encoding="utf-8")).get("session_id") or str(uuid.uuid4())
    else:
        session_id = str(uuid.uuid4())
        session_file.write_text(
            json.dumps(
                {"session_id": session_id, "created": _dt.datetime.now(_dt.timezone.utc).isoformat()},
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    return Prepared(
        engagement_id=engagement_id,
        scope_json=scope_json,
        settings_path=settings_path,
        roe_path=roe_path,
        mcp_config=mcp_config,
        approvals_path=approvals_path,
        pending_path=pending_path,
        session_id=session_id,
        scope=proj,
    )


def build_argv(
    claude_bin: str,
    repo_root: Path,
    prep: Prepared,
    prompt: str,
    permission_mode: str = "default",
) -> list[str]:
    return [
        claude_bin,
        prompt,
        "--add-dir",
        str(repo_root.resolve()),
        "--append-system-prompt-file",
        str(prep.roe_path),
        "--settings",
        str(prep.settings_path),
        "--setting-sources",
        "project,local",
        "--strict-mcp-config",
        "--mcp-config",
        str(prep.mcp_config),
        "--permission-mode",
        permission_mode,
        "--session-id",
        prep.session_id,
        "-n",
        prep.engagement_id,
    ]


def autonomous_prompt(engagement_id: str) -> str:
    return (
        f"Autonomously run Redstrike engagement '{engagement_id}'. Authorization and scope are already "
        f"recorded (RoE appended) — §0 is SATISFIED, do not re-ask. Invoke the redstrike orchestrator "
        f"skill and work the recon phase and non-destructive analysis end to end, gating per the appended "
        f"AUTONOMOUS rules: STOP and summarize at any approval-gated / destructive step instead of proceeding."
    )


def build_autonomous_argv(
    claude_bin: str,
    repo_root: Path,
    prep: Prepared,
    prompt: str,
    allowed_tools: list[str],
    *,
    max_turns: int,
    max_budget: float,
    resume: bool = False,
) -> list[str]:
    argv = [
        claude_bin,
        "-p",
        prompt,
        "--add-dir",
        str(repo_root.resolve()),
        "--append-system-prompt-file",
        str(prep.roe_path),
        "--settings",
        str(prep.settings_path),
        "--setting-sources",
        "project,local",
        "--strict-mcp-config",
        "--mcp-config",
        str(prep.mcp_config),
        "--permission-mode",
        "dontAsk",
        "--output-format",
        "stream-json",
        "--verbose",
        "--max-turns",
        str(max_turns),
        "--max-budget-usd",
        str(max_budget),
    ]
    argv += ["--resume", prep.session_id] if resume else ["--session-id", prep.session_id, "-n", prep.engagement_id]
    # --allowedTools consumes the rest of the line, so it goes LAST.
    argv += ["--allowedTools", *allowed_tools]
    return argv


def gate(prep: Prepared, *, now=None) -> list[str]:
    """Return a list of blocking reasons (empty == clear to launch)."""
    problems: list[str] = []
    ok, issues = scopemod.is_complete(prep.scope)
    if not ok:
        problems.extend(issues)
    open_, why = scopemod.window_open(prep.scope, now=now)
    if not open_:
        problems.append(why)
    return problems


def launch_console(repo: Path, target: Path | None = None, port: int = 8787,
                   background: bool = True, open_browser: bool = True,
                   dry_run: bool = False) -> list[str]:
    """Start scripts/console.py over the engagements (idempotent, won't stack).

    Returns the argv (handy for --dry-run / tests). Background mode detaches and
    returns immediately so callers like `run --console` don't block; dry_run only
    builds the argv.
    """
    script = repo / "scripts" / "console.py"
    tgt = str(target) if target else str(repo / "engagements")
    argv = [sys.executable, str(script), tgt, "--port", str(port)]
    if background:
        argv.append("--background")
    if open_browser:
        argv.append("--open")
    if dry_run:
        return argv
    try:
        subprocess.run(argv, check=False)
    except FileNotFoundError:
        print("note: could not launch the console (python / scripts/console.py missing).", file=sys.stderr)
    return argv


def exec_claude(argv: list[str], cwd: Path) -> int:
    try:
        return subprocess.run(argv, cwd=str(cwd), check=False).returncode
    except KeyboardInterrupt:
        return 130
    except FileNotFoundError:
        print("error: `claude` not found on PATH.", file=sys.stderr)
        return 127
