#!/usr/bin/env python3
"""Redstrike rate / backoff gate — a Claude Code hook (PreToolUse + PostToolUse).

Companion to `scope_gate.py`. Where the scope gate answers *"is this host allowed?"*,
this gate answers *"am I going too fast / am I being blocked?"* — the missing control
that turns the prose `rate_limit_rps` in scope.yaml into something actually enforced,
and that keeps an engagement (especially a bug-bounty program) from getting its IP
banned for hammering or for drilling payloads through a WAF that is already throttling.

Two jobs, two modes, one shared state file:

  • PreToolUse  (default)      — BEFORE a request to host H:
        1. breaker OPEN for H (recent run of block responses) ⇒ DENY, pause until it cools;
        2. the call looks like an auth attempt and H's auth-attempt budget is spent ⇒ DENY
           (lockout avoidance — see the auth-budget section below);
        3. H's requests in the last second ≥ the rps budget ⇒ DENY, space out / add jitter;
        4. otherwise PASS and record the attempt.
  • PostToolUse (`--observe`)  — AFTER a request completes: read the response status from
        the tool output; a block (429/403/503/challenge) trips/escalates H's breaker with
        exponential backoff + jitter, a clean success closes it.

HONESTY (same altitude as scope_gate's own caveats):
  • The auth-attempt budget caps logins per (host, username) under the engagement's lockout
    threshold so a slow spray can't DoS a real account. But confirmation of FAILURE only exists
    at PostToolUse, so it counts every detected attempt as if it could fail, and when it cannot
    recover a username from the command it falls back to a coarse per-host throttle that does NOT
    guarantee any specific account stays unlocked. Detection is heuristic; a login it does not
    recognize is not budgeted, so this REDUCES lockout risk — it does not eliminate it.
  • A PreToolUse hook cannot *sleep* the agent — it can only pass/deny. "Pacing" is therefore
    enforced as a DENY framed as engagement policy ("you are over budget for H — wait/jitter
    before the next request"), which (per roe-gate's framing rule) makes the agent PAUSE and
    re-plan instead of trying to evade. It is backpressure, not a literal throttle.
  • The breaker only learns it is blocked if `--observe` runs and can parse a status out of the
    tool output. Status parsing from free-form Bash/curl text is best-effort (see `parse_status`);
    when it can't tell, it does nothing (fails OPEN for observation) rather than guess a block.
  • State is per-engagement on disk and shared by every parallel agent's hook process, guarded
    by an advisory file lock. If locking is unavailable the gate degrades to best-effort.

Decision contract (identical to scope_gate): on DENY print a PreToolUse JSON decision to stdout
and exit 0; on PASS print nothing and exit 0; `--observe` never denies (records + exits 0). Any
internal error fails OPEN here (a pacing miss must never wedge a legitimate in-scope request —
the scope gate, which fails CLOSED, remains the safety boundary).

Usage (wired by the launcher into settings.json):
  # PreToolUse  (second hook after the scope gate)
  python rate_gate.py --scope <eng>/runtime/scope.json --state <eng>/runtime/rate_state.json  < payload.json
  # PostToolUse
  python rate_gate.py --observe --scope <eng>/runtime/scope.json --state <eng>/runtime/rate_state.json  < payload.json
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
import time
from pathlib import Path

# Reuse the scope gate's host extraction so "what host does this tool call touch?" is answered
# identically by both gates (schemeless URLs, Bash command text, mcp blobs, file-path filtering).
try:  # as a package (normal install)
    from . import scope_gate as sg
except ImportError:  # as a plain script (hook run by path, no package context)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import scope_gate as sg  # type: ignore

# POSIX advisory locking; absent on non-POSIX (e.g. native Windows) → fall back to msvcrt
# byte-range locking below, and only if neither is present degrade to best-effort.
try:
    import fcntl  # type: ignore
except ImportError:  # pragma: no cover - platform dependent
    fcntl = None  # type: ignore

try:
    import msvcrt  # type: ignore
except ImportError:  # pragma: no cover - platform dependent
    msvcrt = None  # type: ignore

# --- tunables (overridable via CLI / scope rules) ---------------------------
WINDOW_SEC = 1.0           # sliding window the rps budget is measured over
DEFAULT_RPS = 5.0          # used only when scope.json carries no rate_limit_rps
BASE_BACKOFF_SEC = 2.0     # first backoff after a single block
MAX_OPEN_SEC = 120.0       # cap on a single backoff interval
BLOCK_STATUSES = frozenset({429, 403, 503})  # statuses that trip the breaker
# Body signatures of an anti-bot/WAF challenge even when the status looks benign (200/503).
_CHALLENGE_RE = re.compile(
    r"(?:cf-mitigated|just a moment|attention required|captcha|checking your browser|"
    r"access denied|request (?:blocked|unsuccessful)|you have been blocked|"
    r"rate.?limit(?:ed)?|too many requests|retry-after)",
    re.IGNORECASE,
)
# Explicit HTTP status line, e.g. "HTTP/1.1 429", "HTTP/2 403".
_STATUS_LINE_RE = re.compile(r"\bHTTP/(?:1\.[01]|2|3)\s+(\d{3})\b")
# A lone 3-digit code on its own line (curl -w '%{http_code}') — the LAST such wins (final response).
_BARE_CODE_RE = re.compile(r"(?m)^\s*([1-5]\d{2})\s*$")

# --- auth-attempt / lockout budget ------------------------------------------
# The rps gate bounds how FAST we go, not how many failed LOGINS we attempt. A slow spray (one
# try per account, paced under the rps budget) can still march an account past its lockout
# threshold — a denial-of-service on a real user. This budget caps auth attempts per
# (host, username) under the engagement's account-lockout threshold so the engagement never
# locks the accounts it is testing.
#
# LIMIT (be honest): confirmation of whether an attempt FAILED only exists at PostToolUse, so
# this counts EVERY detected auth attempt (pass or fail) as if it could fail — conservative on
# purpose. When no username is recoverable from the command, it falls back to a coarse per-host
# spray throttle (keyed "*") and CANNOT guarantee a specific account won't lock; see run_pre.
AUTH_WINDOW_SEC = 1800.0           # the window lockout counters decay over (~most AD policies)
DEFAULT_LOCKOUT_THRESHOLD = 5      # assumed lockout threshold when scope.rules.lockout_threshold is absent
DEFAULT_SPRAY_CAP = 50             # per-host cap on un-attributed (username-unknown) auth attempts / window

# Tools whose command text signals an authentication attempt (login / brute / spray).
_BRUTE_RE = re.compile(
    r"\b(hydra|medusa|ncrack|patator|crackmapexec|cme|netexec|nxc|kerbrute|brutespray|smtp-user-enum)\b",
    re.IGNORECASE,
)
_CRED_PARAM_RE = re.compile(r"(?i)(?:^|[?&\s'\"])(?:password|passwd|pwd|pass)=[^&\s'\"]+")
_BASIC_AUTH_RE = re.compile(r"(?i)authorization\s*:\s*basic\s+\S+")
_CURL_USERPASS_RE = re.compile(r"(?i)(?:^|\s)(?:-u|--user)[ =]\S+:\S+")
# Username extractors (first hit wins); ordered most- to least-specific.
_USER_RES = [
    re.compile(r"(?:^|\s)-l\s+([^\s:]+)"),                           # hydra -l user (lowercase only; -L is a LIST file)
    re.compile(r"(?i)(?:^|\s)(?:-u|--user(?:name)?)[ =]([^\s:&'\"]+)"),
    re.compile(r"(?i)[?&](?:username|user|login|email)=([^&\s'\"]+)"),
    re.compile(r"(?i)\b(?:username|login)=([^&\s'\"]+)"),
    re.compile(r"(?i)://([^/:@\s]+):[^/@\s]+@"),                     # creds in a URL authority
]


# --- state ------------------------------------------------------------------
def _blank_host() -> dict:
    return {"ts": [], "blocks": 0, "open_until": 0.0,
            "last_status": 0, "total_requests": 0, "total_blocks": 0, "auth": {}}


def _host_state(state: dict, host: str) -> dict:
    hosts = state.setdefault("hosts", {})
    hs = hosts.get(host)
    if hs is None:
        hs = _blank_host()
        hosts[host] = hs
    # tolerate a partial/old record
    for k, v in _blank_host().items():
        hs.setdefault(k, v)
    return hs


def prune(ts: list, now: float, window: float = WINDOW_SEC) -> list:
    """Drop timestamps older than the sliding window (in place-safe copy)."""
    cutoff = now - window
    return [t for t in ts if t >= cutoff]


# --- core decisions (pure; unit-tested directly) ----------------------------
def check(hs: dict, now: float, *, rps: float, window: float = WINDOW_SEC) -> dict:
    """Decide whether a request to this host may proceed NOW.

    Mutates `hs` only on PASS (records the attempt). Returns a decision dict
    {'decision': 'pass'|'deny', 'reason': str, 'retry_after': float}.
    """
    open_until = float(hs.get("open_until", 0.0) or 0.0)
    if open_until > now:
        wait = open_until - now
        return {
            "decision": "deny",
            "reason": (f"backing off after {hs.get('blocks', 0)} block response(s) — "
                       f"pause ~{wait:.1f}s before the next request"),
            "retry_after": wait,
        }
    hs["ts"] = prune(list(hs.get("ts", [])), now, window)
    if rps > 0 and len(hs["ts"]) >= rps:
        # oldest in-window attempt frees a slot after it ages out of the window
        wait = max(0.0, (hs["ts"][0] + window) - now)
        return {
            "decision": "deny",
            "reason": (f"rate budget exceeded ({int(rps)} req/s) — "
                       f"space out requests / add jitter (~{wait:.2f}s)"),
            "retry_after": wait,
        }
    hs["ts"].append(now)
    hs["total_requests"] = int(hs.get("total_requests", 0)) + 1
    return {"decision": "pass", "reason": "", "retry_after": 0.0}


def detect_auth(tool_name: str, tool_input: dict) -> tuple[bool, str | None]:
    """Is this tool call an authentication attempt, and against which username (if recoverable)?

    Conservative: only a brute/spray tool, a credential parameter, an HTTP Basic header, or
    `-u user:pass` counts as an auth attempt — ordinary recon does not. Returns (False, None)
    otherwise. The username (when found) keys the per-account budget; absent, the caller falls
    back to the coarse per-host spray throttle.
    """
    ti = tool_input or {}
    if tool_name in ("Bash", "PowerShell"):
        text = str(ti.get("command", ""))
    elif tool_name == "WebFetch":
        text = str(ti.get("url", ""))
    elif tool_name.startswith("mcp__"):
        text = json.dumps(ti, default=str)
    else:
        return (False, None)
    is_auth = bool(
        _BRUTE_RE.search(text) or _CRED_PARAM_RE.search(text)
        or _BASIC_AUTH_RE.search(text) or _CURL_USERPASS_RE.search(text)
    )
    if not is_auth:
        return (False, None)
    for rx in _USER_RES:
        m = rx.search(text)
        if m and m.group(1):
            return (True, m.group(1).lower())
    return (True, None)


def auth_check(hs: dict, key: str, now: float, *, budget: int,
               window: float = AUTH_WINDOW_SEC) -> dict:
    """Bound auth attempts for one budget key (a username, or "*" for un-attributed spray) on this
    host. DENY once `budget` attempts sit inside the window, so we never make the attempt that would
    trip the lockout. Mutates `hs` only on PASS (records the attempt), mirroring `check`.
    """
    auth = hs.setdefault("auth", {})
    rec = auth.get(key) or {"ts": []}
    ts = [t for t in rec.get("ts", []) if t >= now - window]
    if budget > 0 and len(ts) >= budget:
        wait = max(0.0, (ts[0] + window) - now)
        rec["ts"] = ts
        auth[key] = rec
        who = "account" if key != "*" else "host (username unknown)"
        return {
            "decision": "deny",
            "reason": (f"auth-attempt budget reached for {who} ({len(ts)}/{budget} in "
                       f"{int(window)}s) — pausing to avoid locking the account "
                       f"(retry in ~{wait / 60:.0f}m)"),
            "retry_after": wait,
        }
    ts.append(now)
    rec["ts"] = ts
    auth[key] = rec
    return {"decision": "pass", "reason": "", "retry_after": 0.0}


def observe(hs: dict, status: int | None, now: float, *, is_challenge: bool = False,
            base_backoff: float = BASE_BACKOFF_SEC, max_open: float = MAX_OPEN_SEC,
            block_statuses=BLOCK_STATUSES, rng=random.random) -> dict:
    """Fold an observed response into the host's breaker state.

    A block (status in `block_statuses`, or a detected challenge) escalates the breaker with
    exponential backoff + ±20% jitter; a clean success (any non-block status we could read)
    resets it. An unreadable status (None, not a challenge) is a no-op. Returns `hs`.
    """
    blocked = is_challenge or (status is not None and status in block_statuses)
    if blocked:
        hs["blocks"] = int(hs.get("blocks", 0)) + 1
        hs["total_blocks"] = int(hs.get("total_blocks", 0)) + 1
        delay = base_backoff * (2 ** (hs["blocks"] - 1))
        delay = min(delay, max_open)
        delay *= 0.8 + 0.4 * rng()   # jitter so parallel agents don't resynchronize
        hs["open_until"] = now + delay
        if status is not None:
            hs["last_status"] = status
    elif status is not None:
        # a response we could read that is NOT a block ⇒ the host is healthy again
        hs["blocks"] = 0
        hs["open_until"] = 0.0
        hs["last_status"] = status
    return hs


def decide(state: dict, hosts: list[str], now: float, *, rps: float,
           window: float = WINDOW_SEC) -> dict:
    """Run `check` across every host a single tool call touches; the most restrictive wins.

    DENY is returned for the first host that denies (its name is in the reason). Hosts that
    pass have their attempt recorded. Ignorable hosts (localhost/private) are skipped.
    """
    worst = {"decision": "pass", "reason": "", "retry_after": 0.0, "host": ""}
    for host in hosts:
        if not host or sg.is_ignorable(host):
            continue
        hs = _host_state(state, host)
        d = check(hs, now, rps=rps, window=window)
        if d["decision"] == "deny":
            d = dict(d, host=host)
            # prefer the longest wait if several would deny
            if d["retry_after"] >= worst.get("retry_after", 0.0):
                worst = d
    return worst


# --- status parsing (best-effort, documented blind spot) --------------------
def parse_status(text: str) -> tuple[int | None, bool]:
    """Best-effort (status, is_challenge) from arbitrary tool output.

    Order: explicit `HTTP/x NNN` status line (last one = final response after redirects) →
    a lone 3-digit code (curl `-w '%{http_code}'`). A challenge body signature sets the flag
    regardless. Returns (None, False) when nothing is parseable — the caller then no-ops.
    """
    if not text:
        return None, False
    is_challenge = bool(_CHALLENGE_RE.search(text))
    status: int | None = None
    lines = _STATUS_LINE_RE.findall(text)
    if lines:
        status = int(lines[-1])
    else:
        bares = _BARE_CODE_RE.findall(text)
        if bares:
            status = int(bares[-1])
    return status, is_challenge


def _response_text(payload: dict) -> str:
    """Flatten the PostToolUse response payload to searchable text (shape varies by tool)."""
    resp = payload.get("tool_response", payload.get("tool_result", ""))
    if isinstance(resp, (dict, list)):
        return json.dumps(resp, default=str)
    return str(resp or "")


def target_hosts(tool_name: str, tool_input: dict) -> list[str]:
    """External (non-ignorable) hosts a tool call touches, via the scope gate's extractor."""
    ti = tool_input or {}
    if tool_name == "WebFetch":
        raw = str(ti.get("url", ""))
        h = sg._host_of_url(raw)
        blob = raw if h else raw  # extract_targets recovers schemeless hosts
        found = [h] if h else sg.extract_targets(blob)
    elif tool_name in ("Bash", "PowerShell"):
        found = sg.extract_targets(str(ti.get("command", "")))
    elif tool_name.startswith("mcp__"):
        found = sg.extract_targets(json.dumps(ti, default=str))
    else:
        return []
    return [h for h in found if h and not sg.is_ignorable(h)]


# --- persistence (concurrency-safe) -----------------------------------------
def _load_state(fh) -> dict:
    try:
        fh.seek(0)
        raw = fh.read()
        return json.loads(raw) if raw.strip() else {}
    except Exception:
        return {}


def _save_state(fh, state: dict) -> None:
    fh.seek(0)
    fh.truncate()
    json.dump(state, fh)
    fh.flush()
    os.fsync(fh.fileno())


# Byte region (at offset 0) the Windows msvcrt lock contends on; one byte is enough — every
# process locks the same region, so the read-modify-write serializes. Locking past EOF is legal.
_LOCK_BYTES = 1


def _lock(fh) -> None:
    """Take an exclusive cross-process lock on the open state file (POSIX flock or Windows msvcrt)."""
    if fcntl is not None:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
    elif msvcrt is not None:
        fh.seek(0)
        # LK_LOCK blocks (retries ~10x/1s) until the region is free, matching flock(LOCK_EX).
        msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, _LOCK_BYTES)


def _unlock(fh) -> None:
    """Release the lock taken by `_lock` (unlock the same offset-0 region)."""
    if fcntl is not None:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    elif msvcrt is not None:
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, _LOCK_BYTES)


def with_state(state_path: Path, fn):
    """Open state under an exclusive advisory lock, hand the dict to `fn`, persist the result.

    `fn(state) -> (return_value, mutated_state)`. The lock serializes the read-modify-write so
    parallel hook processes can't clobber each other's counters. Uses POSIX `fcntl` where
    available and Windows `msvcrt` byte-range locking otherwise; degrades to best-effort only
    when neither is present.
    """
    state_path.parent.mkdir(parents=True, exist_ok=True)
    # a+ so the file is created if missing and we can read then rewrite
    with open(state_path, "a+", encoding="utf-8") as fh:
        _lock(fh)
        try:
            state = _load_state(fh)
            result, new_state = fn(state)
            _save_state(fh, new_state)
            return result
        finally:
            _unlock(fh)


# --- rps resolution ---------------------------------------------------------
def resolve_rps(scope_path: str, max_rps: float | None) -> float:
    """rate_limit_rps from scope.json (fallback DEFAULT_RPS), clamped by an optional ceiling.

    `--max-rps` lets a bug-bounty profile pace BELOW the scope's number without editing scope.
    """
    rps = DEFAULT_RPS
    try:
        scope = json.loads(Path(scope_path).read_text(encoding="utf-8"))
        v = (scope.get("rules", {}) or {}).get("rate_limit_rps")
        if v is not None:
            rps = float(v)
    except Exception:
        pass
    if max_rps is not None and max_rps > 0:
        rps = min(rps, max_rps)
    return rps


def resolve_lockout_threshold(scope_path: str) -> int:
    """scope.rules.lockout_threshold (the account-lockout threshold for this engagement), or the
    conservative default. The per-account budget allows threshold-1 attempts and denies the one
    that would reach the threshold."""
    try:
        scope = json.loads(Path(scope_path).read_text(encoding="utf-8"))
        v = (scope.get("rules", {}) or {}).get("lockout_threshold")
        if v is not None:
            return max(1, int(v))
    except Exception:
        pass
    return DEFAULT_LOCKOUT_THRESHOLD


# --- hook I/O ---------------------------------------------------------------
def _emit_deny(reason: str) -> None:
    # Framed as engagement pacing policy (NOT a target defense) so the agent PAUSES and re-plans
    # instead of burning turns re-encoding/retrying around its own gate (see roe-gate §6).
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                f"[redstrike rate-gate] engagement pacing policy (NOT a target defense) — {reason}. "
                f"Wait and re-plan; do not retry faster or re-encode around this gate."
            ),
        }
    }))


def run_pre(payload: dict, scope_path: str, state_path: Path, max_rps: float | None,
            now: float | None = None) -> int:
    now = time.time() if now is None else now
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    hosts = target_hosts(tool_name, tool_input)
    if not hosts:
        return 0
    rps = resolve_rps(scope_path, max_rps)
    is_auth, user = detect_auth(tool_name, tool_input)
    threshold = resolve_lockout_threshold(scope_path)

    def _txn(state):
        # Lockout avoidance comes FIRST — locking a real account is worse than being paced.
        if is_auth:
            key = user or "*"
            budget = max(1, threshold - 1) if user else DEFAULT_SPRAY_CAP
            for host in hosts:
                if sg.is_ignorable(host):
                    continue
                ad = auth_check(_host_state(state, host), key, now, budget=budget)
                if ad["decision"] == "deny":
                    return dict(ad, host=host), state
        return decide(state, hosts, now, rps=rps), state

    d = with_state(state_path, _txn)
    if d["decision"] == "deny":
        where = f"{d.get('host', 'target')}"
        _emit_deny(f"{where}: {d['reason']}")
    return 0


def run_observe(payload: dict, state_path: Path, now: float | None = None) -> int:
    now = time.time() if now is None else now
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    hosts = target_hosts(tool_name, tool_input)
    if not hosts:
        return 0
    status, is_challenge = parse_status(_response_text(payload))
    if status is None and not is_challenge:
        return 0  # nothing we can honestly fold in

    def _txn(state):
        for host in hosts:
            observe(_host_state(state, host), status, now, is_challenge=is_challenge)
        return None, state

    with_state(state_path, _txn)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Redstrike rate / backoff gate.")
    ap.add_argument("--scope", default=os.environ.get("REDSTRIKE_SCOPE_FILE", ""))
    ap.add_argument("--state", default=os.environ.get("REDSTRIKE_RATE_STATE", ""))
    ap.add_argument("--observe", action="store_true", help="PostToolUse: fold the response into breaker state")
    ap.add_argument("--max-rps", type=float, default=_env_float("REDSTRIKE_MAX_RPS"),
                    help="clamp the rps budget below scope's rate_limit_rps (bug-bounty profile)")
    args = ap.parse_args(argv)

    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except Exception:
        payload = {}

    state_path = Path(args.state) if args.state else _default_state(args.scope)
    if state_path is None:
        return 0  # nowhere to keep state ⇒ fail OPEN (pacing is best-effort, scope gate still guards)

    try:
        if args.observe:
            return run_observe(payload, state_path)
        return run_pre(payload, args.scope, state_path, args.max_rps)
    except Exception:
        # Fail OPEN: a pacing bug must never wedge a legitimate in-scope request.
        return 0


def _env_float(name: str) -> float | None:
    v = os.environ.get(name)
    try:
        return float(v) if v else None
    except ValueError:
        return None


def _default_state(scope_path: str) -> Path | None:
    if not scope_path:
        return None
    return Path(scope_path).resolve().parent / "rate_state.json"


if __name__ == "__main__":
    raise SystemExit(main())
