"""Generate the per-engagement Claude Code --settings file.

This is where the governance lives (NOT in any SKILL.md): the PreToolUse scope-gate
hook, denies that keep the agent out of the launcher-owned governance files, a modest
pre-approval of read-only tools to cut prompt fatigue, and subagent/ memory bounds.
Offensive tooling is deliberately NOT pre-approved — it stays interactively gated.
"""
from __future__ import annotations

import json
import shlex
from pathlib import Path
from urllib.parse import urlsplit

# Read-only / orchestration tools safe to pre-approve so recon doesn't prompt on
# every step. WebFetch, Bash and the write tools are intentionally absent.
_ALLOW = ["Read", "Grep", "Glob", "Skill", "Agent", "TodoWrite", "WebSearch"]

# Autonomous runs pre-approve WebFetch (in-scope enforced by the hook) and allow Bash /
# PowerShell at the permission layer — but the hook is the real shell gate: it DEFERS any
# shell command the operator didn't pre-allow (`--allow 'Bash(nmap *)'`) or approve, so
# "allow Bash" here means "let the hook decide", not "run anything".
_AUTONOMOUS_EXTRA = ["WebFetch", "Bash", "PowerShell"]

_HOOK_MATCHER = "Bash|PowerShell|WebFetch|Edit|Write|MultiEdit|NotebookEdit|mcp__.*"


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    return [x for x in items if not (x in seen or seen.add(x))]


def autonomous_allowlist(extra: list[str] | None = None) -> list[str]:
    return _dedupe(list(_ALLOW) + list(_AUTONOMOUS_EXTRA) + list(extra or []))


def bash_allow_globs(extra: list[str] | None = None) -> list[str]:
    """Extract the shell pass-globs from --allow entries (the patterns the hook runs
    WITHOUT deferring). `Bash` → `*` (all); `Bash(nmap *)` → `nmap *`."""
    globs: list[str] = []
    for a in extra or []:
        a = a.strip()
        if a in ("Bash", "PowerShell"):
            globs.append("*")
        elif (a.startswith("Bash(") or a.startswith("PowerShell(")) and a.endswith(")"):
            globs.append(a[a.index("(") + 1:-1].strip())
    return _dedupe(globs)


def _host_of(entry: str) -> str:
    """Hostname of an in_scope.urls entry (scheme optional); '' if none parseable."""
    s = str(entry).strip()
    if not s:
        return ""
    try:
        h = urlsplit(s if "://" in s else "//" + s).hostname
    except Exception:
        h = None
    return (h or "").strip().lower()


def build_sandbox(scope: dict | None) -> dict | None:
    """Build the OS-sandbox network block from the engagement scope.

    This is the REAL network boundary on a WSL2/Linux host (the PreToolUse scope gate that
    matches tool *input* is a safety net over it, not a boundary — see hooks/scope_gate.py and
    README "Safety model"). The settings file never emitted a `sandbox` key, so that boundary did
    not exist; this derives `sandbox.network.allowedHosts` from the in-scope domains/cidrs/urls so
    the kernel-level allowlist matches the authorization record.

    Allowlist semantics: everything not listed is denied by the OS sandbox, so out-of-scope assets
    are blocked by omission. We additionally drop any in-scope entry that is itself an EXACT
    out-of-scope entry. We do NOT try to carve an out-of-scope host out of an in-scope wildcard
    (e.g. admin.acme.com under *.acme.com) here — an allowlist can't express that subtraction; the
    scope gate's `classify` (where explicit excludes win, wildcards included) remains the layer that
    catches that case. `allowUnixSockets` is left empty (the engagement needs no extra local sockets
    by default; narrowing it keeps a local-socket escape off the boundary).

    Returns None when no scope is provided (callers then omit the block).
    """
    if not scope:
        return None
    ins = scope.get("in_scope", {}) or {}
    out = scope.get("out_of_scope", {}) or {}
    excluded = {str(x).strip().lower() for x in (out.get("domains") or [])}
    excluded |= {str(x).strip().lower() for x in (out.get("cidrs") or [])}

    allowed: list[str] = []

    def _add(value: str) -> None:
        v = str(value).strip().lower()
        if v and v not in excluded and v not in allowed:
            allowed.append(v)

    for d in ins.get("domains") or []:
        _add(d)
    for c in ins.get("cidrs") or []:
        _add(c)
    for u in ins.get("urls") or []:
        h = _host_of(u)
        if h:
            _add(h)
    return {"network": {"allowedHosts": allowed, "allowUnixSockets": []}}


# Shell-command tokens that perform ACTIVE exploitation (not just recon). A pre-allow glob that
# covers one of these lets the autonomous agent run exploit-class commands WITHOUT the per-command
# deferral — i.e. with no operator sign-off — defeating the approval gate for the highest-impact
# work. These are ordinary tool names (already named across the skills), not source attributions.
_ACTIVE_EXPLOIT_TOKENS = frozenset({
    "sqlmap", "hydra", "medusa", "ncrack", "patator", "crackmapexec", "cme", "netexec", "nxc",
    "commix", "msfconsole", "msfvenom", "metasploit", "ysoserial", "evil-winrm", "responder",
})


def _glob_head(glob: str) -> str:
    """Leading command token of an --allow glob (drop quotes, leading wildcards and any path)."""
    g = glob.strip().strip("'\"").lstrip("*/ ").strip()
    toks = g.split()
    return (toks[0].rsplit("/", 1)[-1].lower()) if toks else ""


def broad_allow_warnings(extra_allow: list[str] | None) -> list[str]:
    """Warnings for `--allow` entries broad enough to run active-exploit commands with no deferral.

    `--allow Bash` / `Bash(*)` pre-allow ANY shell command; a glob like `Bash(sqlmap *)` pre-allows a
    named active-exploit tool; a leading-wildcard glob (`Bash(* --dump)`) can cover exploit commands.
    Each bypasses the autonomous defer gate for a class the approval gate is meant to hold, so the
    launcher surfaces them before launch. Returns human-readable strings (empty when nothing is broad).
    """
    out: list[str] = []
    for a in extra_allow or []:
        a = a.strip()
        if a in ("Bash", "PowerShell"):
            out.append(f"--allow {a}: pre-allows ANY shell command (no per-command deferral) — "
                       f"active-exploit classes would run without operator sign-off")
            continue
        if (a.startswith("Bash(") or a.startswith("PowerShell(")) and a.endswith(")"):
            glob = a[a.index("(") + 1:-1].strip()
            if glob in ("", "*"):
                out.append(f"--allow {a}: wildcard pre-allow runs any shell command without deferral")
                continue
            head = _glob_head(glob)
            if head in _ACTIVE_EXPLOIT_TOKENS:
                out.append(f"--allow {a}: pre-allows '{head}' (an active-exploit tool) to run without deferral")
            elif glob.startswith("*"):
                out.append(f"--allow {a}: leading-wildcard glob is broad enough to cover active-exploit commands")
    return out


def build_hook_command(
    python_exe: str, hook_script: Path, scope_json: Path, extra_args: list[str] | None = None
) -> str:
    parts = [python_exe, str(hook_script), "--scope", str(scope_json)] + list(extra_args or [])
    return " ".join(shlex.quote(str(x)) for x in parts)


def build_rate_hook_command(
    python_exe: str, rate_script: Path, scope_json: Path, state_json: Path,
    *, observe: bool = False, max_rps: float | None = None,
) -> str:
    """Command for the rate/backoff gate (rate_gate.py). `observe=True` is the PostToolUse
    mode that folds the response status into the breaker; default is the PreToolUse pacing gate."""
    parts = [python_exe, str(rate_script), "--scope", str(scope_json), "--state", str(state_json)]
    if observe:
        parts.append("--observe")
    if max_rps is not None:
        parts += ["--max-rps", str(max_rps)]
    return " ".join(shlex.quote(str(x)) for x in parts)


def render_settings(
    *,
    python_exe: str,
    hook_script: Path,
    scope_json: Path,
    mode: str = "interactive",
    extra_allow: list[str] | None = None,
    extra_deny: list[str] | None = None,
    gate_policy: Path | None = None,
    approvals: Path | None = None,
    rate_script: Path | None = None,
    state_json: Path | None = None,
    max_rps: float | None = None,
    scope: dict | None = None,
) -> dict:
    allow = autonomous_allowlist(extra_allow) if mode == "autonomous" else list(_ALLOW)
    # The rate/backoff gate lives next to the scope gate and keeps its state next to scope.json.
    if rate_script is None:
        rate_script = hook_script.parent / "rate_gate.py"
    if state_json is None:
        state_json = scope_json.parent / "rate_state.json"
    hook_extra: list[str] = []
    if mode == "autonomous":
        hook_extra = ["--defer"]
        if gate_policy:
            hook_extra += ["--policy", str(gate_policy)]
        if approvals:
            hook_extra += ["--approvals", str(approvals)]
    deny = [
        "Write(runtime/**)",
        "Edit(runtime/**)",
        "MultiEdit(runtime/**)",
        "Write(scope.yaml)",
        "Edit(scope.yaml)",
        "MultiEdit(scope.yaml)",
    ]
    if extra_deny:
        deny.extend(extra_deny)
    settings: dict = {
        "$comment": "Generated by the redstrike CLI — do not hand-edit; re-run `redstrike run`.",
        "permissions": {
            "allow": allow,
            "deny": deny,
        },
        "hooks": {
            # Scope gate FIRST (it fails closed and is the real boundary); the rate/backoff
            # gate runs after it as pacing backpressure (fails open). A PostToolUse observer
            # feeds the breaker the response status so "being blocked" becomes "back off".
            "PreToolUse": [
                {
                    "matcher": _HOOK_MATCHER,
                    "hooks": [
                        {
                            "type": "command",
                            "command": build_hook_command(python_exe, hook_script, scope_json, hook_extra),
                        },
                        {
                            "type": "command",
                            "command": build_rate_hook_command(
                                python_exe, rate_script, scope_json, state_json, max_rps=max_rps
                            ),
                        },
                    ],
                }
            ],
            "PostToolUse": [
                {
                    "matcher": _HOOK_MATCHER,
                    "hooks": [
                        {
                            "type": "command",
                            "command": build_rate_hook_command(
                                python_exe, rate_script, scope_json, state_json, observe=True
                            ),
                        }
                    ],
                }
            ],
        },
        "env": {
            "REDSTRIKE_SCOPE_FILE": str(scope_json),
            "REDSTRIKE_RATE_STATE": str(state_json),
            "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
            "CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH": "3",
            "CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS": "8",
        },
    }
    # The OS-sandbox network boundary (the real confinement on WSL2/Linux), derived from scope.
    # Emitted whenever the scope projection is available; inert on hosts without an OS sandbox.
    sandbox = build_sandbox(scope)
    if sandbox is not None:
        settings["sandbox"] = sandbox
    return settings


def write_settings(path: str | Path, settings: dict) -> None:
    Path(path).write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
