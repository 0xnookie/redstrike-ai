#!/usr/bin/env python3
"""Redstrike PreToolUse scope gate — a Claude Code hook.

Self-contained (stdlib only) so Claude Code can run it as a plain script no matter
how the CLI was installed. It reads the PreToolUse JSON payload on stdin, loads the
engagement's generated runtime/scope.json, and DENIES tool calls that reach an
explicitly out-of-scope asset, that target a host not in scope (WebFetch / active
Bash), or that write to the engagement's governance files (self-approval guard).
Everything else is passed through to normal permission handling.

IMPORTANT (honesty): a hook matching tool *input* is a safety net, not a boundary.
Bash command text can hide a target the regex misses, so the real network boundary
is the OS sandbox allowlist (settings.sandbox.network) on a WSL2/Linux host. This
gate catches the obvious and the explicit, and fails closed when scope is missing.

Decision contract: on DENY, print a PreToolUse JSON decision to stdout and exit 0.
On PASS, print nothing and exit 0. On any internal error, fail closed (deny).

Usage (wired by the launcher into settings.json):
  python scope_gate.py --scope <engagement>/runtime/scope.json  < payload.json
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import ipaddress
import json
import os
import re
import sys
from pathlib import Path

_URL = re.compile(r"https?://[^\s\"'<>|)\]}]+", re.IGNORECASE)
_HOST = re.compile(r"(?<![\w.-])(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?![\w.-])")
_IPV4 = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])")
_IGNORABLE_TLDS = (".localhost", ".test", ".example", ".invalid")
_WRITE_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
_PATH_KEYS = ("file_path", "notebook_path", "path")
_SHELL_TOOLS = ("Bash", "PowerShell")


def fingerprint(tool_name: str, tool_input: dict) -> str:
    """Stable id for an approval. Keyed on the semantic payload (command/url) so it
    survives a defer→resume round-trip (verified: the input is identical on resume)."""
    ti = tool_input or {}
    if tool_name in _SHELL_TOOLS:
        key = str(ti.get("command", ""))
    elif tool_name == "WebFetch":
        key = str(ti.get("url", ""))
    else:
        key = json.dumps(ti, sort_keys=True, default=str)
    return hashlib.sha256((tool_name + "\x00" + key).encode("utf-8")).hexdigest()


def _bash_allowed(cmd: str, globs) -> bool:
    cmd = cmd.strip()
    for g in globs or []:
        if g == "*" or fnmatch.fnmatch(cmd, g):
            return True
    return False


# --- host / scope matching --------------------------------------------------
def normalize_host(h: str) -> str:
    h = h.strip().lower().rstrip(".")
    if h.startswith("[") and "]" in h:  # [ipv6]
        return h[1 : h.index("]")]
    if h.count(":") == 1:  # host:port (not ipv6)
        h = h.split(":", 1)[0]
    return h


def domain_matches(host: str, pattern: str) -> bool:
    host = normalize_host(host)
    pattern = pattern.strip().lower().rstrip(".")
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    return host == pattern


def _as_ip(token: str):
    try:
        return ipaddress.ip_address(token)
    except ValueError:
        return None


def ip_in_cidrs(ip, cidrs: list[str]) -> bool:
    for c in cidrs:
        try:
            if ip in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def is_ignorable(token: str) -> bool:
    ip = _as_ip(token)
    if ip is not None:
        return bool(
            ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
        )
    host = normalize_host(token)
    if host in ("localhost", ""):
        return True
    return host.endswith(_IGNORABLE_TLDS)


def classify(token: str, scope: dict) -> str:
    """Return 'out', 'in', or 'unknown' for a host or IP token."""
    ins = scope.get("in_scope", {}) or {}
    out = scope.get("out_of_scope", {}) or {}
    ip = _as_ip(token)
    host = normalize_host(token)
    # explicit excludes win
    if ip is not None:
        if ip_in_cidrs(ip, out.get("cidrs", []) or []):
            return "out"
    else:
        if any(domain_matches(host, p) for p in (out.get("domains", []) or [])):
            return "out"
    # in scope
    if ip is not None:
        if ip_in_cidrs(ip, ins.get("cidrs", []) or []):
            return "in"
    else:
        if any(domain_matches(host, p) for p in (ins.get("domains", []) or [])):
            return "in"
        # hosts embedded in in_scope.urls count too
        for u in ins.get("urls", []) or []:
            uh = _host_of_url(u)
            if uh and domain_matches(host, uh):
                return "in"
    return "unknown"


def _host_of_url(url: str) -> str | None:
    from urllib.parse import urlsplit

    try:
        return normalize_host(urlsplit(url).hostname or "")
    except Exception:
        return None


def extract_targets(text: str) -> list[str]:
    found: list[str] = []
    for m in _URL.finditer(text):
        h = _host_of_url(m.group(0))
        if h:
            found.append(h)
    for m in _IPV4.finditer(text):
        found.append(m.group(0))
    for m in _HOST.finditer(text):
        found.append(normalize_host(m.group(0)))
    # de-dupe preserving order
    seen, uniq = set(), []
    for t in found:
        if t and t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq


# --- protected governance paths --------------------------------------------
def protected_paths(scope_file: Path) -> list[Path]:
    runtime = scope_file.resolve().parent
    engagement = runtime.parent
    return [runtime, engagement / "scope.yaml"]


def _targets_protected(raw_path: str, protected: list[Path], cwd: Path) -> bool:
    if not raw_path:
        return False
    p = Path(raw_path)
    if not p.is_absolute():
        p = cwd / p
    try:
        p = p.resolve()
    except Exception:
        p = (cwd / raw_path).absolute()
    for prot in protected:
        try:
            if p == prot or prot in p.parents:
                return True
        except Exception:
            continue
    return False


# --- decision ---------------------------------------------------------------
def evaluate(
    tool_name: str,
    tool_input: dict,
    scope: dict,
    protected: list[Path],
    cwd: Path,
    *,
    defer: bool = False,
    bash_allow=(),
    approvals=frozenset(),
) -> dict:
    """Return {'decision': 'deny'|'defer'|'pass', 'reason': str, ['fingerprint': str]}.

    In `defer` mode (autonomous runs) an in-scope shell command that the operator has
    not pre-allowed (`--allow`) or approved is DEFERRED for sign-off instead of run.
    """
    tool_input = tool_input or {}

    if tool_name in _WRITE_TOOLS:
        for key in _PATH_KEYS:
            if key in tool_input and _targets_protected(str(tool_input[key]), protected, cwd):
                return _deny(
                    f"write to engagement-governance path '{tool_input[key]}' is blocked "
                    f"(scope/runtime are launcher-owned, not agent-writable)"
                )
        return _pass()

    if tool_name == "WebFetch":
        raw = str(tool_input.get("url", ""))
        host = _host_of_url(raw)
        if not host:
            # Schemeless / opaque URL (e.g. "evil.com/x"): urlsplit finds no netloc, so a bare
            # hostname would otherwise fail OPEN past the gate. Recover the authority host from the
            # raw string (first host/IP wins — that's the fetch target) before deciding.
            recovered = extract_targets(raw)
            host = recovered[0] if recovered else ""
        if not host:
            return _pass()
        k = classify(host, scope)
        if k == "out":
            return _deny(f"WebFetch target '{host}' is explicitly OUT of scope")
        if k == "in" or is_ignorable(host):
            return _pass()
        return _deny(f"WebFetch target '{host}' is not in the engagement scope")

    if tool_name in ("Bash", "PowerShell"):
        cmd = str(tool_input.get("command", ""))
        offenders_out, offenders_unknown = [], []
        for t in extract_targets(cmd):
            k = classify(t, scope)
            if k == "out":
                offenders_out.append(t)
            elif k == "unknown" and not is_ignorable(t):
                offenders_unknown.append(t)
        if offenders_out:
            return _deny(f"command references OUT-of-scope host(s): {', '.join(offenders_out)}")
        if offenders_unknown:
            return _deny(
                "command references host(s) not in scope: "
                f"{', '.join(offenders_unknown)} — add to scope.yaml or correct the target"
            )
        if defer:
            fp = fingerprint(tool_name, tool_input)
            if fp in approvals:
                return _pass()  # operator approved this exact command earlier
            if _bash_allowed(cmd, bash_allow):
                return _pass()  # operator pre-allowed this pattern via --allow
            return _defer(f"shell command needs operator approval: {cmd.strip()[:90]}", fp)
        return _pass()

    if tool_name.startswith("mcp__"):
        # MCP tools (e.g. a browser/automation server) carry targets in free-form, per-server
        # input we can't schema-validate — so stringify the whole input and scan it for hosts/URLs.
        # BLIND SPOT: once a tab/session is already attached, follow-up actions (click/type on an
        # element ref) carry no host and are invisible here — same limit as an opaque Bash command.
        blob = json.dumps(tool_input, default=str)
        offenders_out, offenders_unknown = [], []
        for t in extract_targets(blob):
            k = classify(t, scope)
            if k == "out":
                offenders_out.append(t)
            elif k == "unknown" and not is_ignorable(t):
                offenders_unknown.append(t)
        if offenders_out:
            return _deny(f"MCP call references OUT-of-scope host(s): {', '.join(offenders_out)}")
        if offenders_unknown:
            return _deny(
                "MCP call references host(s) not in scope: "
                f"{', '.join(offenders_unknown)} — add to scope.yaml or correct the target"
            )
        return _pass()

    return _pass()


def _deny(reason: str) -> dict:
    return {"decision": "deny", "reason": reason}


def _defer(reason: str, fp: str) -> dict:
    return {"decision": "defer", "reason": reason, "fingerprint": fp}


def _pass() -> dict:
    return {"decision": "pass", "reason": ""}


# --- hook I/O ---------------------------------------------------------------
def _emit(decision: str, reason: str) -> None:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": f"[redstrike scope-gate] {reason}",
        }
    }))


def _emit_deny(reason: str) -> None:
    # Frame as engagement policy, not a target defense, so the agent re-plans instead
    # of burning turns trying to re-encode / retry around its own gate.
    _emit("deny", f"engagement policy (NOT a target defense) — {reason}. Re-plan within scope; "
                  f"do not retry or re-encode around this gate.")


def _emit_defer(reason: str) -> None:
    _emit("defer", f"pending operator approval — {reason}. Summarize and stop; do not route around the gate.")


def _load_bash_allow(policy_path: str) -> list:
    if not policy_path:
        return []
    try:
        return list(json.loads(Path(policy_path).read_text(encoding="utf-8")).get("bash_allow", []) or [])
    except Exception:
        return []


def _load_approvals(approvals_path: str) -> frozenset:
    if not approvals_path:
        return frozenset()
    try:
        return frozenset(json.loads(Path(approvals_path).read_text(encoding="utf-8")).get("approved", []) or [])
    except Exception:
        return frozenset()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Redstrike PreToolUse scope gate.")
    ap.add_argument("--scope", default=os.environ.get("REDSTRIKE_SCOPE_FILE", ""))
    ap.add_argument("--defer", action="store_true", help="autonomous: defer un-approved shell for sign-off")
    ap.add_argument("--policy", default="", help="gate-policy.json (bash_allow globs)")
    ap.add_argument("--approvals", default="", help="approvals.json (approved fingerprints)")
    args = ap.parse_args(argv)

    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except Exception:
        payload = {}
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    cwd = Path(payload.get("cwd") or os.getcwd())

    scope_file = Path(args.scope) if args.scope else None
    if not scope_file or not scope_file.is_file():
        # Fail closed: the gate only matches active tools, so deny rather than
        # run an offensive action with no scope record.
        _emit_deny("scope record unavailable (runtime/scope.json missing) — refusing active tool")
        return 0
    try:
        scope = json.loads(scope_file.read_text(encoding="utf-8"))
        decision = evaluate(
            tool_name, tool_input, scope, protected_paths(scope_file), cwd,
            defer=args.defer,
            bash_allow=_load_bash_allow(args.policy),
            approvals=_load_approvals(args.approvals),
        )
    except Exception as e:  # fail closed on any internal error
        _emit_deny(f"scope-gate internal error ({type(e).__name__}) — failing closed")
        return 0

    if decision["decision"] == "deny":
        _emit_deny(decision["reason"])
    elif decision["decision"] == "defer":
        _emit_defer(decision["reason"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
