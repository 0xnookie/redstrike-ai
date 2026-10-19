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
def evaluate(tool_name: str, tool_input: dict, scope: dict, protected: list[Path], cwd: Path) -> dict:
    """Return {'decision': 'deny'|'pass', 'reason': str}."""
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
        host = _host_of_url(str(tool_input.get("url", "")))
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
        return _pass()

    return _pass()


def _deny(reason: str) -> dict:
    return {"decision": "deny", "reason": reason}


def _pass() -> dict:
    return {"decision": "pass", "reason": ""}


# --- hook I/O ---------------------------------------------------------------
def _emit_deny(reason: str) -> None:
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"[redstrike scope-gate] {reason}",
        }
    }
    print(json.dumps(out))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Redstrike PreToolUse scope gate.")
    ap.add_argument("--scope", default=os.environ.get("REDSTRIKE_SCOPE_FILE", ""))
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
        decision = evaluate(tool_name, tool_input, scope, protected_paths(scope_file), cwd)
    except Exception as e:  # fail closed on any internal error
        _emit_deny(f"scope-gate internal error ({type(e).__name__}) — failing closed")
        return 0

    if decision["decision"] == "deny":
        _emit_deny(decision["reason"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
