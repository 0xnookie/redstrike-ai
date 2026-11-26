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
import datetime as _dt
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
# Final labels that mark a dotted token as a FILESYSTEM PATH, not a network host. The bare-host
# regex (_HOST) otherwise reads `scope.json`, `homepage.html`, `scan.txt`, `wp-config.php` and
# `--include=*.py` as hostnames, classifies them "unknown" (not in scope) and DENIES the command —
# which blocks the agent from reading/writing its own engagement artifacts and from saving tool
# output (`curl ... -o out.html`), stalling an autonomous run. Real web targets carry a scheme
# (caught by _URL) or a genuine TLD, so filtering these removes the false positives without opening
# a schemeless out-of-scope host; the OS sandbox network allowlist remains the actual boundary. A
# few entries double as ccTLDs (sh/md/py/rs/go/rb/pl) — as a BARE token in a shell command they are
# overwhelmingly filenames, and a real target on one of those TLDs is written with a scheme.
_FILE_EXTS = frozenset("""
json jsonl ndjson yaml yml toml ini cfg conf env properties lock
txt md markdown rst log csv tsv xml html htm xhtml pdf
js mjs cjs ts tsx jsx css scss sass less
py sh bash zsh fish ps1 rb go rs java kt kts c h cpp hpp cc cxx php pl lua sql r
zip tar gz tgz bz2 xz zst 7z rar jar war
png jpg jpeg gif svg ico webp bmp tiff mp4 mp3 wav webm
pem crt cer der key pub p12 pfx jks keystore pcap pcapng cap har
bin exe dll so dylib dat db sqlite sqlite3 bak tmp swp pid sock map
""".split())
_WRITE_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
_PATH_KEYS = ("file_path", "notebook_path", "path")
_SHELL_TOOLS = ("Bash", "PowerShell")

# --- write-gate (RoE §2 parity with scripts/rs_http.py) --------------------
# The autonomous/headless mirror of rs_http's write-gate: a MUTATING HTTP request (curl/wget/httpie)
# to an in-scope host needs a covering approval grant in runtime/approvals.json, else it is DENIED.
# A SAFETY NET, not a boundary (same honesty as the host regex above): an obfuscated mutation can slip
# it, and the authoritative chokepoint for bespoke HTTP is rs_http.py — so rs_http.py commands are
# skipped here (they self-enforce) to avoid double-gating. Disabled by RS_WRITE_GATE=0.
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_HTTP_METHOD_WORDS = ("get", "head", "post", "put", "patch", "delete", "options", "trace", "connect")
_WRITE_GATE_ENV = "RS_WRITE_GATE"
_APPROVALS_NAME = "approvals.json"
# curl/wget explicit method flag (`-X POST`, `--request=PUT`, `--method=DELETE`), or httpie `http POST url`.
_HTTP_METHOD_FLAG = re.compile(
    r"""(?:-X|--request|--method)\s*=?\s*['"]?(get|head|post|put|patch|delete|options)\b"""
    r"""|\bhttps?\s+(get|head|post|put|patch|delete|options)\b""", re.IGNORECASE)


def write_gate_enabled() -> bool:
    """ON by default; RS_WRITE_GATE=0/off/false/no/disabled turns the write-gate OFF (operator
    kill-switch — kept identical to scripts/rs_http.py.write_gate_enabled)."""
    v = os.environ.get(_WRITE_GATE_ENV)
    if v is None:
        return True
    return v.strip().lower() not in ("0", "off", "false", "no", "disable", "disabled")


def detect_mutating_http(cmd: str):
    """Best-effort: is this shell command a MUTATING HTTP request to a URL? Returns (method, host,
    path) or None. rs_http.py commands return None (rs_http self-enforces the write-gate, so the hook
    does not double-gate them). A probe declared on an rs_http command (`--probe`) is likewise rs_http's
    to allow. Safety net, not a boundary."""
    low = cmd.lower()
    if "rs_http" in low:
        return None
    m = _HTTP_METHOD_FLAG.search(cmd)
    if not m:
        return None
    method = (m.group(1) or m.group(2) or "").upper()
    if method not in _MUTATING_METHODS:
        return None
    um = _URL.search(cmd)
    if um:
        url = um.group(0)
        host = _host_of_url(url)
        from urllib.parse import urlsplit
        try:
            path = (urlsplit(url).path or "").rstrip("/")
        except Exception:
            path = ""
    else:                                   # schemeless target (e.g. httpie 'http POST example.com/x')
        hosts = extract_targets(cmd)
        host, path = (hosts[0] if hosts else ""), ""
    if not host:
        return None
    return method, host, path


def _grant_text(grant: dict) -> str:
    return " ".join(str(grant.get(k, "") or "")
                    for k in ("scope_granted", "note", "justification", "delete_path")).lower()


def _grant_names_method(text: str, method: str) -> bool:
    method = method.lower()
    named = [m for m in _HTTP_METHOD_WORDS if re.search(r"\b" + m + r"\b", text)]
    return (method in named) if named else True


_PATH_TOKEN = re.compile(r"/[0-9a-z._~%\-/{}]*", re.I)   # a path-like token inside grant prose


def _path_covered(text: str, path: str) -> bool:
    """Does the grant text authorize this request PATH? Root/empty is host-level; otherwise the
    endpoint must appear verbatim OR the grant must name a PARENT path of it (so `/api/comments`
    covers `/api/comments/123`) — but a sibling (`/api/profile`) never covers it. Identical to
    rs_http._path_covered."""
    req = (path or "").lower()
    if not req:
        return True
    if req in text:
        return True
    for t in _PATH_TOKEN.findall(text):
        p = t.rstrip("/.,);:'\"").lower()
        if p and p != "/" and req.startswith(p + "/"):
            return True
    return False


def grant_covers(grant: dict, method: str, host: str, path: str) -> bool:
    """True iff this grant authorizes `method` to `host``path`. Host MUST be named; the SPECIFIC
    endpoint path must be covered (verbatim or via a named parent path) — this is what stops a grant
    being stretched to an endpoint it never mentioned. Identical semantics to rs_http._grant_covers."""
    text = _grant_text(grant)
    host = (host or "").lower()
    if host and host not in text:
        return False
    if not _path_covered(text, path):
        return False
    return _grant_names_method(text, method)


def grant_reversibility_ok(grant: dict) -> bool:
    """A reversible-self-write is INVALID without a delete_path; reversible:true needs delete_path OR
    cleanup_method (roe-gate.md §2 / approvals.schema.json). Identical to rs_http._grant_reversibility_ok."""
    wc = str(grant.get("write_class", "") or "").lower()
    if wc == "reversible-self-write":
        return bool(grant.get("delete_path"))
    if grant.get("reversible") is True:
        return bool(grant.get("delete_path") or grant.get("cleanup_method"))
    return True


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


def _leading_token(s: str) -> str:
    """Leading command/glob token: drop surrounding quotes, leading wildcards and any path,
    take the first whitespace-delimited token's basename, lowercase. Mirrors settings._glob_head
    (kept here so the gate stays self-contained / stdlib-only)."""
    g = s.strip().strip("'\"").lstrip("*/ ").strip()
    toks = g.split()
    return (toks[0].rsplit("/", 1)[-1].lower()) if toks else ""


def _narrow_allows(head: str, cmd: str, globs) -> bool:
    """True when a NARROW operator pre-allow glob explicitly names `head` and matches the command —
    the escape hatch for an always-defer (active-exploit) token. A blanket '*' / '' allow is NOT a
    narrow pre-allow (it never lets an exploit token skip the gate); a leading-wildcard glob like
    '* --dump' names no tool, so its leading token won't equal `head` either."""
    cmd = cmd.strip()
    for g in globs or []:
        gs = str(g).strip()
        if gs in ("", "*"):
            continue
        if _leading_token(gs) == head and fnmatch.fnmatch(cmd, gs):
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
    # Normalize the scope entry the SAME way as the target: strip a port ("host:port" authored in
    # scope.yaml), a trailing dot and case. Targets are always matched port-less, so a port left on
    # the scope pattern would never match and would silently put the whole host out of scope.
    pattern = normalize_host(pattern)
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
        tok = normalize_host(m.group(0))
        # A bare dotted token ending in a known file/code extension is a path argument
        # (scope.json, out.html, *.py), not a network host — skip it. Schemed targets were
        # already collected by _URL above, so this only drops false positives.
        if tok.rsplit(".", 1)[-1] in _FILE_EXTS:
            continue
        # A dotted token immediately followed by "(" is a code attribute/method call
        # (json.load(, d.get(, subprocess.run(, os.path.join(), not a network host — a real
        # hostname is never written with a trailing "(". Catches inline python/js in a Bash
        # command that would otherwise be denied as an out-of-scope "host".
        if m.end() < len(text) and text[m.end()] == "(":
            continue
        found.append(tok)
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


# --- engagement window ------------------------------------------------------
# Tools that reach the target over the network; the engagement window governs these. Local file
# writes (Edit/Write/...) are left to the governance-path guard so findings/notes can still be
# written up after the window closes.
_ACTIVE_TOOLS = ("WebFetch", "Bash", "PowerShell")


def _parse_iso(s: str):
    """ISO-8601 → aware datetime (UTC default), or None. Self-contained (hook may run as a plain
    script with no package context), so this intentionally duplicates scope.parse_iso."""
    if not s:
        return None
    s = str(s).strip().replace("Z", "+00:00")
    try:
        d = _dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=_dt.timezone.utc)
    return d


def window_denial(scope: dict, now: _dt.datetime) -> str | None:
    """Reason to DENY active tooling because the engagement window is not current, else None.

    Enforced CONTINUOUSLY in-session (launch.gate only checks it once at launch, so a long run
    could otherwise keep hitting the target after the authorized window closed). Only engages when
    the window carries a parseable bound: a scope with no window (e.g. the gate's own unit fixtures)
    is not denied here — launch.gate already blocks a launch whose scope has no window.
    """
    win = scope.get("window") or {}
    end = _parse_iso(win.get("end", ""))
    if end is not None and now > end:
        return f"engagement window has closed (ended {win.get('end')}) — no active tooling permitted"
    start = _parse_iso(win.get("start", ""))
    if start is not None and now < start:
        return f"engagement window has not opened yet (starts {win.get('start')})"
    return None


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
    always_defer=frozenset(),
    grants=(),
    now: _dt.datetime | None = None,
) -> dict:
    """Return {'decision': 'deny'|'defer'|'pass', 'reason': str, ['fingerprint': str]}.

    In `defer` mode (autonomous runs) an in-scope shell command that the operator has
    not pre-allowed (`--allow`) or approved is DEFERRED for sign-off instead of run.

    WRITE-DISCIPLINE (defer mode): a MUTATING HTTP command (curl/wget/httpie POST/PUT/PATCH/DELETE)
    to an in-scope host with NO covering approval grant in `grants` is DENIED — the autonomous mirror
    of rs_http's write-gate (RoE §2). rs_http.py commands self-enforce and are skipped. An exact-command
    approval still passes; RS_WRITE_GATE=0 disables it.

    `always_defer` is the set of active-exploit leading tokens (e.g. sqlmap, msfconsole) that
    DEFER even under a broad `Bash`/`*` pre-allow — so RCE / active-exploit class steps always
    reach the operator — UNLESS the operator pre-allowed that exact tool with a narrow glob
    (`Bash(sqlmap *)`) or approved the exact command. DENY (out-of-scope) always takes precedence.

    Active (target-reaching) tools are additionally DENIED once the engagement window has closed
    (or before it opens) — fail-closed, framed as engagement policy.
    """
    tool_input = tool_input or {}
    now = now or _dt.datetime.now(_dt.timezone.utc)

    # Engagement window: closed/not-yet-open ⇒ deny any active, target-reaching tool.
    if tool_name in _ACTIVE_TOOLS or tool_name.startswith("mcp__"):
        wd = window_denial(scope, now)
        if wd:
            return _deny(wd)

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
                return _pass()  # operator approved this exact command earlier (human sign-off)
            # WRITE-DISCIPLINE (RoE §2 parity with rs_http): a mutating HTTP request to an in-scope
            # host needs a covering approval grant — else DENY (hard stop). rs_http.py commands
            # self-enforce + are skipped; RS_WRITE_GATE=0 disables this.
            if write_gate_enabled():
                mut = detect_mutating_http(cmd)
                if mut:
                    w_method, w_host, w_path = mut
                    if classify(w_host, scope) == "in":
                        covering = [g for g in (grants or []) if grant_covers(g, w_method, w_host, w_path)]
                        if not covering:
                            return _deny(
                                f"mutating {w_method} {w_host}{w_path or '/'} has no covering approval "
                                f"grant in runtime/{_APPROVALS_NAME} — record a grant (roe-gate.md §2), "
                                f"or route the write through scripts/rs_http.py, which gates + logs it")
                        if not any(grant_reversibility_ok(g) for g in covering):
                            return _deny(
                                f"the covering approval for {w_method} {w_host}{w_path or '/'} claims a "
                                f"reversible basis but records no delete_path — a reversible-self-write "
                                f"is INVALID without one (roe-gate.md §2); it is a production write")
            head = _leading_token(cmd)
            if head in always_defer and not _narrow_allows(head, cmd, bash_allow):
                # Active-exploit / RCE class: a broad `Bash` / `*` pre-allow does NOT auto-run it —
                # only an explicit per-command approval or a narrow, operator-named pre-allow
                # (Bash(sqlmap *)) lets it through. Keeps unattended exploitation behind the human gate.
                return _defer(
                    f"active-exploit step '{head}' needs operator approval: {cmd.strip()[:90]}", fp
                )
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
    # A deferral QUEUES the item and the run KEEPS GOING — it must never read as "stop the run".
    _emit("defer", f"pending operator approval — {reason}. Record it, SKIP this step for now, and "
                   f"CONTINUE other in-scope, non-gated work; the operator approves pending items and "
                   f"the run resumes. Do not retry or route around the gate.")


def _load_bash_allow(policy_path: str) -> list:
    if not policy_path:
        return []
    try:
        return list(json.loads(Path(policy_path).read_text(encoding="utf-8")).get("bash_allow", []) or [])
    except Exception:
        return []


def _load_always_defer(policy_path: str) -> list:
    """Active-exploit tokens that defer even under a broad allow (gate-policy.json
    `always_defer_tokens`). Default empty when absent so older policy files stay back-compatible."""
    if not policy_path:
        return []
    try:
        return list(
            json.loads(Path(policy_path).read_text(encoding="utf-8")).get("always_defer_tokens", []) or []
        )
    except Exception:
        return []


def _load_approvals(approvals_path: str) -> frozenset:
    if not approvals_path:
        return frozenset()
    try:
        return frozenset(json.loads(Path(approvals_path).read_text(encoding="utf-8")).get("approved", []) or [])
    except Exception:
        return frozenset()


def _load_grants(approvals_path: str) -> list:
    """The RoE approval-grant ledger (`grants[]`) from approvals.json — the SAME file that carries the
    launcher's {approved, resume_queue}; we read only `grants`. Missing/unreadable ⇒ [] (the write-gate
    then denies un-granted mutations). Mirrors rs_http.load_grants."""
    if not approvals_path:
        return []
    try:
        d = json.loads(Path(approvals_path).read_text(encoding="utf-8"))
        if isinstance(d, dict) and isinstance(d.get("grants"), list):
            return d["grants"]
    except Exception:
        pass
    return []


# --- chain-of-custody producer ---------------------------------------------
# The gate is the one component that sees EVERY target-reaching tool call before it runs, so it is the
# natural producer of the engagement's immutable audit log (roe-gate.md §4) — the timestamped who/what/
# when trail that no engagement previously carried. It appends one record per gate decision (deny/defer,
# and every active/target-reaching pass) to runtime/audit.jsonl (schema: skills/_contract/audit.schema.json),
# binding the decision to the scope in force via sha256(scope.json). Self-contained + best-effort: a
# custody-log failure must NEVER break the hook flow, so every append is wrapped and swallowed.
_AUDIT_FILENAME = "audit.jsonl"


def _file_sha256(path) -> str:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except Exception:
        return ""


def _audit_target(tool_name: str, tool_input: dict) -> str:
    """A concise target for the custody line: tool + the primary host/URL it reaches (when resolvable)."""
    ti = tool_input or {}
    host = ""
    try:
        if tool_name == "WebFetch":
            raw = str(ti.get("url", ""))
            host = _host_of_url(raw) or (extract_targets(raw) or [""])[0]
        elif tool_name in _SHELL_TOOLS:
            hosts = extract_targets(str(ti.get("command", "")))
            host = hosts[0] if hosts else ""
        elif tool_name.startswith("mcp__"):
            hosts = extract_targets(json.dumps(ti, default=str))
            host = hosts[0] if hosts else ""
    except Exception:
        host = ""
    return f"{tool_name}:{host}" if host else (tool_name or "unknown")


def _append_audit(runtime_dir, *, actor: str, action: str, target: str, detail: str,
                  sha256: str = "") -> None:
    """Append one custody record (JSONL) to <runtime_dir>/audit.jsonl. Never raises."""
    try:
        rec = {
            "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "actor": actor,
            "action": action,
            "target": target or "",
            "detail": (detail or "")[:300],
        }
        if sha256:
            rec["sha256"] = sha256
        p = Path(runtime_dir) / _AUDIT_FILENAME
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
    except Exception:
        pass


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
        if scope_file is not None:  # best-effort custody line even on a missing-scope deny
            _append_audit(scope_file.parent, actor="scope-gate", action="deny",
                          target=_audit_target(tool_name, tool_input),
                          detail="scope record unavailable — refusing active tool")
        return 0
    scope_sha = _file_sha256(scope_file)
    runtime_dir = scope_file.resolve().parent
    try:
        scope = json.loads(scope_file.read_text(encoding="utf-8"))
        decision = evaluate(
            tool_name, tool_input, scope, protected_paths(scope_file), cwd,
            defer=args.defer,
            bash_allow=_load_bash_allow(args.policy),
            approvals=_load_approvals(args.approvals),
            always_defer=frozenset(_load_always_defer(args.policy)),
            grants=_load_grants(args.approvals),
        )
    except Exception as e:  # fail closed on any internal error
        _emit_deny(f"scope-gate internal error ({type(e).__name__}) — failing closed")
        _append_audit(runtime_dir, actor="scope-gate", action="deny",
                      target=_audit_target(tool_name, tool_input),
                      detail=f"internal error ({type(e).__name__}) — failing closed", sha256=scope_sha)
        return 0

    # Chain of custody: record every deny/defer, and every active/target-reaching PASS (Bash/PowerShell/
    # WebFetch/mcp__). Local file reads/searches (the bulk of PASSes) are not target-reaching and are not
    # logged, keeping the trail the meaningful who/what/when of the engagement's offensive surface.
    dec = decision["decision"]
    is_active = tool_name in _ACTIVE_TOOLS or tool_name.startswith("mcp__")
    if dec != "pass" or is_active:
        _append_audit(runtime_dir, actor="scope-gate", action=dec,
                      target=_audit_target(tool_name, tool_input),
                      detail=(decision.get("reason") or f"{tool_name} passed scope gate"),
                      sha256=scope_sha)

    if dec == "deny":
        _emit_deny(decision["reason"])
    elif dec == "defer":
        _emit_defer(decision["reason"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
