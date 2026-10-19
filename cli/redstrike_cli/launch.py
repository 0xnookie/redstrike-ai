"""Assemble runtime artifacts and launch (or dry-run) the Claude Code engine."""
from __future__ import annotations

import datetime as _dt
import json
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

from . import roe as roemod
from . import scope as scopemod
from . import settings as settingsmod


@dataclass
class Prepared:
    engagement_id: str
    scope_json: Path
    settings_path: Path
    roe_path: Path
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


def prepare_runtime(engagement_dir: Path, repo_root: Path, python_exe: str) -> Prepared:
    engagement_dir = engagement_dir.resolve()
    scope_yaml = engagement_dir / "scope.yaml"
    if not scope_yaml.is_file():
        raise FileNotFoundError(f"no scope.yaml in {engagement_dir} — run `redstrike init` first")

    runtime = engagement_dir / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    scope_json = runtime / "scope.json"
    proj = scopemod.derive_scope_json(scope_yaml, scope_json)  # re-derive from canonical YAML

    settings_path = runtime / "settings.json"
    settings = settingsmod.render_settings(
        python_exe=python_exe, hook_script=hook_script(), scope_json=scope_json
    )
    settingsmod.write_settings(settings_path, settings)

    engagement_id = engagement_dir.name
    roe_path = runtime / "roe.md"
    roe_path.write_text(roemod.render_roe(proj, engagement_id), encoding="utf-8")

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
    return Prepared(engagement_id, scope_json, settings_path, roe_path, session_id, proj)


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
        "--permission-mode",
        permission_mode,
        "--session-id",
        prep.session_id,
        "-n",
        prep.engagement_id,
    ]


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


def exec_claude(argv: list[str], cwd: Path) -> int:
    try:
        return subprocess.run(argv, cwd=str(cwd), check=False).returncode
    except KeyboardInterrupt:
        return 130
    except FileNotFoundError:
        print("error: `claude` not found on PATH.", file=sys.stderr)
        return 127
