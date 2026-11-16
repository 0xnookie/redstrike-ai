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
from . import audit as auditmod
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
    scope_sha256: str = ""           # fingerprint of the live scope.yaml at this launch
    scope_integrity_warning: str = ""  # set when the live scope.yaml drifted from the acknowledged one


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


def _seed_coverage_ledger(engagement_dir: Path, repo_root: Path, python_exe: str) -> None:
    """Create a baseline coverage_ledger.json if absent (best-effort, never fatal).

    `coverage.py --plan` with no recon signals attempts every in-scope category (the
    recall-safe default), so "which vuln categories were attempted vs skipped" is tracked
    from the start instead of depending on the orchestrator to remember to create a ledger.
    The orchestrator re-plans it with recon signals + the real phases and marks entries as it
    runs; `redstrike verify` validates it at close. Skipped when the ledger already exists
    (don't clobber a refined one) or coverage.py isn't present."""
    ledger = engagement_dir / "coverage_ledger.json"
    script = repo_root / "scripts" / "coverage.py"
    if ledger.is_file() or not script.is_file():
        return
    try:
        subprocess.run(
            [python_exe, str(script), "--plan", "--engagement", str(engagement_dir)],
            cwd=str(repo_root), check=False,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30,
        )
    except Exception as e:
        # Not fatal, but no longer silent: a failed seed means coverage tracking starts blind, which
        # later shows up as a degraded-empty diagnosis — record WHY in the engagement's error.log.
        ts = _dt.datetime.now(_dt.timezone.utc).isoformat()
        auditmod.append_line(
            engagement_dir / "runtime" / "error.log",
            auditmod.redact_text(f"[{ts}] _seed_coverage_ledger failed: {type(e).__name__}: {e}"),
        )


def _seed_notebook(engagement_dir: Path, repo_root: Path, python_exe: str) -> None:
    """Create a baseline notebook.json if absent (best-effort, never fatal).

    Defense-in-depth so the console's Notebook view populates — RoE + test accounts (from scope) at
    minimum — even before recon, and so a run that stops early is never indistinguishable from one that
    never ran. `notebook.py --plan` is idempotent: it merges and never clobbers executor/human edits, so
    the orchestrator enriches this post-recon (recon_intel + seeded leads). Skipped when a notebook
    already exists (don't re-seed a refined one) or notebook.py isn't present. Mirrors
    `_seed_coverage_ledger` down to the error.log-on-failure pattern."""
    notebook = engagement_dir / "notebook.json"
    script = repo_root / "scripts" / "notebook.py"
    if notebook.is_file() or not script.is_file():
        return
    try:
        subprocess.run(
            [python_exe, str(script), "--plan", "--engagement", str(engagement_dir)],
            cwd=str(repo_root), check=False,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30,
        )
    except Exception as e:
        ts = _dt.datetime.now(_dt.timezone.utc).isoformat()
        auditmod.append_line(
            engagement_dir / "runtime" / "error.log",
            auditmod.redact_text(f"[{ts}] _seed_notebook failed: {type(e).__name__}: {e}"),
        )


def prepare_runtime(
    engagement_dir: Path,
    repo_root: Path,
    python_exe: str,
    *,
    mode: str = "interactive",
    extra_allow: list[str] | None = None,
    resume: bool = False,
) -> Prepared:
    engagement_dir = engagement_dir.resolve()
    scope_yaml = engagement_dir / "scope.yaml"
    if not scope_yaml.is_file():
        raise FileNotFoundError(f"no scope.yaml in {engagement_dir} — run `redstrike init` first")

    runtime = engagement_dir / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    scope_json = runtime / "scope.json"
    proj = scopemod.derive_scope_json(scope_yaml, scope_json)  # re-derive from canonical YAML

    # scope.yaml integrity: verify the live canonical record against the fingerprint the operator
    # acknowledged at init. A drift is SURFACED (and bound into the audit head), not silent — this is
    # the first thing that checks the "signed canonical authorization record" it claims to be. It
    # warns rather than blocks: scope legitimately evolves between runs (e.g. a discovered subdomain).
    scope_sha256 = auditmod.scope_fingerprint(scope_yaml)
    scope_integrity_warning = _verify_scope_integrity(engagement_dir, scope_sha256)

    # Track category coverage from the start (deterministic routing, not model discretion).
    _seed_coverage_ledger(engagement_dir, repo_root, python_exe)
    # Seed the engagement notebook so the console's Notebook view (RoE + test accounts) populates even
    # before recon; the orchestrator enriches it post-recon. Idempotent — notebook.py merges, never clobbers.
    _seed_notebook(engagement_dir, repo_root, python_exe)

    gate_policy = runtime / "gate-policy.json"
    approvals_path = runtime / "approvals.json"
    pending_path = runtime / "approvals_pending.json"
    if mode == "autonomous":
        gate_policy.write_text(
            json.dumps(
                {
                    "mode": "autonomous",
                    "bash_allow": settingsmod.bash_allow_globs(extra_allow),
                    # Active-exploit tokens the scope gate defers even under a broad `Bash`/`*` allow,
                    # so unattended exploitation still reaches the operator (see scope_gate.evaluate).
                    "always_defer_tokens": sorted(settingsmod._ACTIVE_EXPLOIT_TOKENS),
                },
                indent=2,
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
        scope=proj,  # populates the OS-sandbox network allowlist from the engagement scope
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

    # Session id: claude REJECTS a reused `--session-id` ("Session ID … is already in use"),
    # so a fresh (non-resume) launch must mint a NEW id every time — reusing the stored one only
    # works through `--resume`. The stored id is therefore the resume anchor: the last fresh run's
    # session. (Reusing it on a plain re-launch is what made every 2nd autonomous run die at the
    # boundary marker.)
    session_file = runtime / "session.json"
    stored = None
    if session_file.is_file():
        try:
            stored = json.loads(session_file.read_text(encoding="utf-8")).get("session_id")
        except Exception:
            stored = None
    if resume and stored:
        session_id = stored
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
        scope_sha256=scope_sha256,
        scope_integrity_warning=scope_integrity_warning,
    )


def _verify_scope_integrity(engagement_dir: Path, current_sha: str) -> str:
    """Compare the live scope.yaml fingerprint to the one acknowledged at init (authorization.json).

    Returns a warning string on drift (or an unreadable record), else "". Returns "" when no baseline
    was ever recorded (pre-integrity engagements) so older engagements are not falsely flagged.
    """
    auth_path = engagement_dir / "runtime" / "authorization.json"
    try:
        acknowledged = json.loads(auth_path.read_text(encoding="utf-8")).get("scope_sha256", "")
    except Exception:
        acknowledged = ""
    if not acknowledged or not current_sha:
        return ""
    if acknowledged != current_sha:
        return (
            "scope.yaml has CHANGED since authorization was acknowledged at init "
            f"(acknowledged sha256 {acknowledged[:12]}…, now {current_sha[:12]}…) — "
            "confirm the change is authorized; the new fingerprint is recorded in the audit head."
        )
    return ""


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
        f"Autonomously run Redstrike engagement '{engagement_id}' END TO END within scope. Authorization "
        f"and scope are recorded (RoE appended) — §0 is SATISFIED, do not re-ask. Invoke the redstrike "
        f"orchestrator skill and drive the WHOLE pipeline, not just recon: run recon and build the "
        f"coverage, surface, and notebook ledgers; then hunt EVERY routed/pending vulnerability category "
        f"with non-destructive detection and a benign PoC (xss, sqli, idor, ssrf, and the rest), each via "
        f"its context feeder and gated by its independent *-verify reviewer subagent; re-converge and run "
        f"the recall-audit; then chain accepted findings and assemble the report. Do NOT stop after recon. "
        f"Only the genuinely approval-gated phases (exploitation / post-exploitation / RCE / destructive) "
        f"are gated: when such a step is not pre-allowed it DEFERS for operator approval — record it, skip "
        f"it for now, and CONTINUE other in-scope work; a deferral is the intended gate, never a reason to "
        f"halt the run. Anything out of scope or outside the window is a HARD STOP. This may be the first "
        f"pass or a resumed session — pick up from the current ledger / notebook state either way."
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
