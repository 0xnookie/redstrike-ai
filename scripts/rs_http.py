#!/usr/bin/env python3
"""rs_http.py -- the ONE reusable, engagement-aware HTTP primitive for bespoke probes.

Why this exists (a real failure it prevents): a live engagement re-rolled the same
urllib+proxy+login boilerplate in ~6 separate ad-hoc scripts (login -> set proxy ->
request -> parse), each re-implementing an HTTP client, and every one of them IGNORED
the scope's `rate_limit_rps` cap. tooling.md bars hand-rolling a tool's core job and
mandates that a genuinely-needed bespoke primitive be written ONCE, parameterized, in
scripts/. This is that primitive: the legitimate exceptions (business-logic abuse,
authed multi-step probes, a race single-packet) point their HTTP at THIS, instead of a
seventh copy of the same login/proxy/request boilerplate.

It is engagement-aware, so a bespoke probe inherits the engagement's guardrails for free:
  * SCOPE   -- refuses (hard-stop, non-zero exit / ScopeError) any URL whose host is
               explicitly out_of_scope, or is not matched by in_scope. Matching mirrors
               the framework's scope gate exactly (``*.`` wildcard domains, CIDRs,
               hosts embedded in in_scope.urls; explicit excludes win).
  * RATE    -- a real client-side throttle: it sleeps to keep the GLOBAL request rate
               <= the scope's `rules.rate_limit_rps` (conservative default when unset).
               The budget is enforced ACROSS ALL CONCURRENT PROCESSES, not per-process:
               the read-modify-write of the shared sliding window (runtime/rs_http_rate.json)
               happens under an OS file lock, and each call RESERVES its send-slot in that
               window BEFORE it sleeps — so K parallel agents sum to <= the cap instead of
               K x the cap (the exact aggregate-rate blind spot that gets a shared egress IP
               WAF-banned estate-wide). nuclei at -rl 18 against a 5-rps engagement, or three
               autonomous agents each pacing to the cap, is exactly what this stops.
  * PROXY   -- routes through RS_PROXY / HTTPS_PROXY / HTTP_PROXY (or --proxy) so every
               request lands in the operator's Burp/Caido history; TLS tolerant by
               default (the interception proxy's CA).
  * COOKIES -- a persistent Mozilla cookie jar file (--cookies) for the authed-probe use
               case: log in once, reuse the session across probes.
  * LOG     -- appends every request/response (method, url, status, timing, sizes, rung)
               as JSONL to <engagement>/runtime/http_log.jsonl, with Authorization /
               Cookie / token values REDACTED to a marker (secrets never hit disk).

Usable BOTH ways:
  CLI        python scripts/rs_http.py --engagement engagements/acme-2026-10 \
                 GET https://app.acme.com/me -H 'Authorization: Bearer T' --cookies jar.txt
  import     from rs_http import request
             r = request("GET", "https://app.acme.com/me", engagement=eng,
                         headers={"Authorization": "Bearer T"})
             print(r.status, len(r.body))

Stdlib only (urllib / ssl / http.cookiejar / json / time / argparse), to match scripts/*.py.
`python scripts/rs_http.py --selftest` exercises the pure logic (no network).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import http.cookiejar
import ipaddress
import json
import os
import re
import ssl
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlsplit, urlunsplit
from urllib.request import (HTTPCookieProcessor, HTTPSHandler, ProxyHandler,
                            Request, build_opener)

# ‹redacted› (U+2039/U+203A guillemets) — the marker secrets become in the log. Distinctive so a
# grep for a leaked token never collides with it, and so "is it redacted?" is unambiguous.
REDACTED = "‹redacted›"

DEFAULT_RPS = 5.0            # conservative pace when scope carries no rate_limit_rps (matches rate_gate)
RATE_WINDOW_SEC = 1.0        # the sliding window the rps budget is measured over
LOG_NAME = "http_log.jsonl"
RATE_STATE_NAME = "rs_http_rate.json"
RATE_LOCK_NAME = "rs_http_rate.lock"   # OS file lock serialising the shared-window read-modify-write
RATE_LOCK_TIMEOUT_SEC = 20.0           # how long to contend for the lock before degrading (best-effort)
RATE_LOCK_STALE_SEC = 20.0             # steal a lock older than this (a crashed holder must not wedge us)
RATE_MAX_KEEP = 256                    # cap the persisted window so the state file can't grow unbounded
DEFAULT_UA = "redstrike-rs_http/1"   # generic client name — never the operator's identity

# Request/response header names whose VALUE is a secret -> redacted in the log (lower-cased compare).
_SECRET_HEADERS = frozenset({
    "authorization", "proxy-authorization", "authentication",
    "cookie", "set-cookie", "x-api-key", "api-key", "x-auth-token",
    "x-amz-security-token", "x-csrf-token", "x-xsrf-token", "x-session-token",
})
# Query / form param NAMES whose value is a secret -> value redacted in the logged URL.
_SECRET_PARAM = re.compile(
    r"(?i)(?:^|_|-)?(token|passwd|password|pwd|secret|api[_-]?key|access[_-]?key|"
    r"auth|session|sig|signature|assertion|code|otp)")

_IGNORABLE_TLDS = (".localhost", ".test", ".example", ".invalid")

# --------------------------------------------------------------------------- write-gate (RoE §2)
# A mutating request needs a covering approval grant, OR a declared probe that cannot persist state.
# This is the mechanical twin of roe-gate.md §2 + write-vs-probe.md: rs_http is the single HTTP
# chokepoint, so it is the place to ENFORCE write-discipline, not just scope + rate. Two real field
# incidents motivate it: (1) a non-reversible production comment created under a "reversible self-write"
# grant that did NOT actually cover the endpoint; (2) a genuinely-benign no-artifact probe blocked
# because nothing distinguished probe from write.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})      # reads — NEVER gated
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})   # the gated verbs
# A declared probe cannot persist state (write-vs-probe.md); these are its allowed bases. Both the
# task's `reversed-via-delete_path` spelling and the contract's `reversible-self-write` are accepted.
PROBE_BASES = frozenset({"safe-method", "validation-failing-body",
                         "reversed-via-delete_path", "reversible-self-write"})
APPROVALS_NAME = "approvals.json"                 # the RoE grant ledger lives here (shares the file
                                                  # with the launcher's {approved, resume_queue})
WRITE_GATE_ENV = "RS_WRITE_GATE"                  # set to 0/off/false/no to DISABLE the write-gate
_HTTP_METHOD_WORDS = ("get", "head", "post", "put", "patch", "delete", "options", "trace", "connect")


class ScopeError(RuntimeError):
    """Raised when a request target is out-of-scope / not in scope — the hard stop."""


class WriteGateError(RuntimeError):
    """Raised when a MUTATING request has no covering approval grant (and is not a declared probe) —
    the write-discipline hard stop, the same altitude as ScopeError (RoE §2 / write-vs-probe.md)."""


# --------------------------------------------------------------------------- scope matching
# Vendored, self-contained copies of the framework scope gate's host matching so scripts/ stays
# stdlib-only and import-free (the cli package is not importable from a bare scripts/ run). This
# mirrors how cli/.../scope_gate.py itself duplicates scope.parse_iso to stay self-contained; the
# semantics are intentionally identical to scope_gate.classify so a bespoke probe and the live gate
# agree on what is in scope.
def normalize_host(h: str) -> str:
    h = (h or "").strip().lower().rstrip(".")
    if h.startswith("[") and "]" in h:          # [ipv6]
        return h[1:h.index("]")]
    if h.count(":") == 1:                        # host:port (not ipv6)
        h = h.split(":", 1)[0]
    return h


def domain_matches(host: str, pattern: str) -> bool:
    host, pattern = normalize_host(host), normalize_host(pattern)
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    return host == pattern


def _as_ip(token: str):
    try:
        return ipaddress.ip_address(token)
    except ValueError:
        return None


def ip_in_cidrs(ip, cidrs) -> bool:
    for c in cidrs or []:
        try:
            if ip in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def is_ignorable(token: str) -> bool:
    """localhost / private / loopback / link-local / reserved — not an in-scope external target."""
    ip = _as_ip(token)
    if ip is not None:
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast)
    host = normalize_host(token)
    if host in ("localhost", ""):
        return True
    return host.endswith(_IGNORABLE_TLDS)


def host_of_url(url: str):
    try:
        return normalize_host(urlsplit(url).hostname or "")
    except Exception:
        return None


def classify(token: str, scope: dict) -> str:
    """'out' (explicitly excluded), 'in' (matched by in_scope), or 'unknown'. Explicit excludes win."""
    ins = scope.get("in_scope", {}) or {}
    out = scope.get("out_of_scope", {}) or {}
    ip = _as_ip(token)
    host = normalize_host(token)
    # explicit excludes win
    if ip is not None:
        if ip_in_cidrs(ip, out.get("cidrs", [])):
            return "out"
    elif any(domain_matches(host, p) for p in (out.get("domains", []) or [])):
        return "out"
    # in scope
    if ip is not None:
        if ip_in_cidrs(ip, ins.get("cidrs", [])):
            return "in"
    else:
        if any(domain_matches(host, p) for p in (ins.get("domains", []) or [])):
            return "in"
        for u in ins.get("urls", []) or []:        # hosts embedded in in_scope.urls count too
            uh = host_of_url(u)
            if uh and domain_matches(host, uh):
                return "in"
    return "unknown"


def scope_verdict(url: str, scope: dict) -> tuple[bool, str]:
    """(allowed, reason). An out-of-scope / unknown-and-not-ignorable host is refused."""
    host = host_of_url(url)
    if not host:
        return False, f"could not parse a host from URL {url!r}"
    k = classify(host, scope)
    if k == "out":
        return False, f"{host} is explicitly OUT of scope"
    if k == "in":
        return True, f"{host} is in scope"
    if is_ignorable(host):
        return True, f"{host} is a local/ignorable host"
    return False, (f"{host} is not in the engagement scope — add it to scope.yaml in_scope "
                   f"or correct the target")


# --------------------------------------------------------------------------- scope loading
def resolve_rps(scope: dict, max_rps: float | None = None) -> float:
    """rate_limit_rps from the scope (conservative DEFAULT_RPS when unset), optionally clamped below by
    --max-rps (a bug-bounty profile can pace under the scope number without editing scope)."""
    rps = DEFAULT_RPS
    v = (scope.get("rules", {}) or {}).get("rate_limit_rps")
    if v is not None:
        try:
            rps = float(v)
        except (TypeError, ValueError):
            pass
    if max_rps is not None and max_rps > 0:
        rps = min(rps, max_rps)
    return rps


def load_scope(engagement) -> dict:
    """Load the engagement's authoritative scope record. Prefers the signed scope.yaml (the instruction's
    source of truth) and falls back to the launcher-derived runtime/scope.json (pure JSON) — either yields
    the same in_scope/out_of_scope/rules shape the matcher needs."""
    eng = Path(engagement)
    y = eng / "scope.yaml"
    if y.is_file():
        try:
            return _load_yaml(y.read_text(encoding="utf-8"))
        except Exception:
            pass   # fall through to the derived JSON
    j = eng / "runtime" / "scope.json"
    if j.is_file():
        return json.loads(j.read_text(encoding="utf-8"))
    raise ScopeError(f"no scope.yaml or runtime/scope.json under {eng} — cannot scope-check requests")


def _load_yaml(text: str) -> dict:
    """PyYAML when present, else a tiny stdlib reader for the 2-level maps / sequences / scalars that
    scope.yaml uses (mirrors cli/.../yamlio so scripts/ needs no YAML dependency)."""
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text) or {}
    except ImportError:
        return _mini_yaml(text)


def _strip_comment(s: str) -> str:
    out, q = [], None
    for ch in s:
        if q:
            out.append(ch)
            if ch == q:
                q = None
        elif ch in ('"', "'"):
            q = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
    return "".join(out).rstrip()


def _yscalar(v: str):
    v = v.strip()
    if v in ("", "~") or v.lower() == "null":
        return None
    if v == "[]":
        return []
    if v == "{}":
        return {}
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        return v[1:-1]
    low = v.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if re.match(r"^-?\d+$", v):
        return int(v)
    if re.match(r"^-?\d+\.\d+$", v):
        return float(v)
    return v


def _mini_yaml(text: str) -> dict:
    lines = text.split("\n")
    n = len(lines)

    def indent(i):
        return len(lines[i]) - len(lines[i].lstrip(" "))

    def skip(i):
        while i < n and (lines[i].strip() == "" or lines[i].strip().startswith("#")):
            i += 1
        return i

    def parse_map(i, base):
        res: dict = {}
        while True:
            i = skip(i)
            if i >= n or indent(i) < base:
                break
            if indent(i) > base:
                i += 1
                continue
            line = _strip_comment(lines[i].strip())
            if line.startswith("- ") or line == "-":
                break
            if ":" not in line:
                i += 1
                continue
            key, _, rest = line.partition(":")
            key, rest = key.strip(), rest.strip()
            i += 1
            if rest in (">", "|"):                       # block scalar — collect, not needed for matching
                body, blk = [], rest
                while i < n and (lines[i].strip() == "" or indent(i) > base):
                    body.append(lines[i].strip())
                    i += 1
                res[key] = (" " if blk == ">" else "\n").join(b for b in body if b != "").strip()
            elif rest == "":
                j = skip(i)
                if j < n and indent(j) > base:
                    nxt = _strip_comment(lines[j].strip())
                    if nxt.startswith("- ") or nxt == "-":
                        res[key], i = parse_seq(j, indent(j))
                    else:
                        res[key], i = parse_map(j, indent(j))
                else:
                    res[key] = None
            else:
                res[key] = _yscalar(rest)
        return res, i

    def parse_seq(i, base):
        items: list = []
        while True:
            i = skip(i)
            if i >= n or indent(i) < base:
                break
            line = _strip_comment(lines[i].strip())
            if not (line.startswith("- ") or line == "-"):
                break
            val = line[1:].strip()
            i += 1
            items.append(_yscalar(val) if val else None)
        return items, i

    data, _ = parse_map(skip(0), 0)
    return data


# --------------------------------------------------------------------------- write-gate
def write_gate_enabled() -> bool:
    """The write-gate is ON by default; RS_WRITE_GATE=0/off/false/no/disabled turns it OFF (the
    operator kill-switch for a misfire — the gate is the component MOST able to over-block)."""
    v = os.environ.get(WRITE_GATE_ENV)
    if v is None:
        return True
    return v.strip().lower() not in ("0", "off", "false", "no", "disable", "disabled")


def load_grants(engagement) -> list:
    """The RoE approval-grant ledger (`grants[]`) from <engagement>/runtime/approvals.json (roe-gate.md
    §2 / approvals.schema.json). The SAME file may also carry the launcher's autonomous-deferral store
    ({approved, resume_queue}); we read ONLY `grants`. Missing / unreadable / wrong-shape ⇒ []
    (best-effort load; the caller decides whether a missing ledger means refuse or no-context)."""
    try:
        p = Path(engagement) / "runtime" / APPROVALS_NAME
        if p.is_file():
            d = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(d, dict) and isinstance(d.get("grants"), list):
                return d["grants"]
    except Exception:
        pass
    return []


def _req_path(url: str) -> str:
    """The request path, normalised for matching: no query/fragment, no trailing slash ('' for root)."""
    try:
        return (urlsplit(url).path or "").rstrip("/")
    except Exception:
        return ""


def _grant_text(grant: dict) -> str:
    """The free-text fields of a grant that can NAME the authorized target/action, lower-cased. The
    schema's `scope_granted` is operator prose ('POST a test comment to app.acme.com/api/comments'),
    so matching scans it (+ note / justification / delete_path) for the host, endpoint and method."""
    return " ".join(str(grant.get(k, "") or "")
                    for k in ("scope_granted", "note", "justification", "delete_path")).lower()


def _grant_names_method(text: str, method: str) -> bool:
    """A grant that NAMES one or more HTTP methods covers only those; a grant that names none is
    method-unrestricted (covers any mutating verb for the endpoint it authorizes)."""
    method = method.lower()
    named = [m for m in _HTTP_METHOD_WORDS if re.search(r"\b" + m + r"\b", text)]
    return (method in named) if named else True


_PATH_TOKEN = re.compile(r"/[0-9a-z._~%\-/{}]*", re.I)   # a path-like token inside grant prose


def _path_covered(text: str, path: str) -> bool:
    """Does the grant text authorize this request PATH? A root/empty path is host-level (host match
    suffices). Otherwise the endpoint must appear verbatim in the grant, OR the grant must name a
    PARENT path of it (so a grant for `/api/comments` also covers `/api/comments/123`). Crucially it
    will NOT treat a sibling (`/api/profile`) as covering `/api/comments` — that is incident #1."""
    req = (path or "").lower()
    if not req:
        return True
    if req in text:                            # the endpoint appears verbatim in the grant
        return True
    for t in _PATH_TOKEN.findall(text):        # a grant-named parent path covers a sub-resource
        p = t.rstrip("/.,);:'\"").lower()
        if p and p != "/" and req.startswith(p + "/"):
            return True
    return False


def _grant_covers(grant: dict, method: str, host: str, path: str) -> bool:
    """True iff this grant authorizes a mutating `method` to `host``path`. The host MUST be named, and
    the SPECIFIC endpoint path must be covered (verbatim or via a named parent path) — this is exactly
    what stops a grant from being stretched to an endpoint it never mentioned (incident #1)."""
    text = _grant_text(grant)
    host = (host or "").lower()
    if host and host not in text:
        return False
    if not _path_covered(text, path):
        return False
    return _grant_names_method(text, method)


def _grant_reversibility_ok(grant: dict) -> bool:
    """A grant whose basis is reversible is INVALID without a recorded undo route (roe-gate.md §2):
    a `reversible-self-write` write_class REQUIRES a `delete_path`; `reversible: true` requires a
    `delete_path` OR a `cleanup_method` (approvals.schema.json). Any other class (production-write /
    destructive / probe) does not claim reversibility here, so it is not refused on this ground."""
    wc = str(grant.get("write_class", "") or "").lower()
    if wc == "reversible-self-write":
        return bool(grant.get("delete_path"))
    if grant.get("reversible") is True:
        return bool(grant.get("delete_path") or grant.get("cleanup_method"))
    return True


def write_gate_verdict(method: str, url: str, grants, *, probe: bool = False,
                       probe_basis: str | None = None, context_present: bool = True):
    """Decide the write-gate for one request. Returns (allowed: bool, basis_or_reason: str, kind: str)
    where kind ∈ {read, disabled, no-context, probe, approved, refuse}.

    Contract (write-vs-probe.md + roe-gate.md §2):
      * a SAFE method (GET/HEAD/OPTIONS/TRACE) is a read — NEVER gated;
      * RS_WRITE_GATE off ⇒ allow (operator kill-switch);
      * no engagement/approvals context (no runtime dir) ⇒ allow — never break the read-heavy call
        sites / unit tests that carry no grant ledger;
      * a declared `probe=True` with a valid `probe_basis` ⇒ allow + LOG (a probe cannot persist
        state, so it bypasses the approval requirement but is recorded for audit);
      * otherwise a mutating method needs a grant that COVERS the target (host+endpoint+method) AND is
        reversibility-valid (a reversible basis without a delete_path is refused); no covering/valid
        grant ⇒ REFUSE (hard stop)."""
    method = method.upper()
    if method in SAFE_METHODS:
        return True, "read (safe method — never gated)", "read"
    if not write_gate_enabled():
        return True, f"write-gate disabled via {WRITE_GATE_ENV}", "disabled"
    if not context_present:
        return True, "no engagement/approvals context — write-gate not applied", "no-context"
    if probe:
        pb = (probe_basis or "").strip().lower()
        if pb not in PROBE_BASES:
            return (False,
                    f"probe=True requires a valid probe_basis ({'/'.join(sorted(PROBE_BASES))}) "
                    f"— got {probe_basis!r}; a probe MUST declare why it cannot persist state", "refuse")
        return True, f"probe:{pb}", "probe"
    host = host_of_url(url)
    path = _req_path(url)
    covering = [g for g in (grants or []) if _grant_covers(g, method, host, path)]
    if not covering:
        return (False,
                f"no covering approval in runtime/{APPROVALS_NAME} for mutating {method} "
                f"{host}{path or '/'} — record a grant (roe-gate.md §2) or declare a probe", "refuse")
    if not any(_grant_reversibility_ok(g) for g in covering):
        return (False,
                f"the covering approval for {method} {host}{path or '/'} claims a reversible basis "
                f"but records no delete_path — a reversible-self-write is INVALID without one "
                f"(roe-gate.md §2); it is a production write and needs the full gate", "refuse")
    return True, "covered by a recorded approval grant", "approved"


# --------------------------------------------------------------------------- rate throttle
def _prune_reservations(reservations, now: float, window: float) -> list:
    """Drop send-slots that can no longer constrain a future one (older than one window before `now`),
    keep every future reservation, and bound the list so the persisted state can't grow without limit."""
    horizon = now - window
    kept = sorted(t for t in reservations if t >= horizon)
    return kept[-RATE_MAX_KEEP:] if len(kept) > RATE_MAX_KEEP else kept


def _throttle_sleep(timestamps, rps: float, now: float,
                    window: float = RATE_WINDOW_SEC) -> tuple[float, list]:
    """Pure sliding-window SLOT RESERVER: given the shared send-slots `timestamps` (recent + already-
    reserved future slots, pooled across ALL concurrent processes via the file-locked state file) and
    the rps cap, return (sleep_seconds, updated_timestamps).

    The new request's SEND time is reserved no sooner than `window` after the `rps`-th most recent
    already-reserved send — so at most `rps` sends ever land in any `window` (an initial burst of up to
    `rps` is allowed, then one slot frees per window). `updated_timestamps` INCLUDES the new reservation;
    the caller persists it UNDER THE LOCK *before* it sleeps, so a concurrent process sees this slot and
    reserves AFTER it. That is what makes the budget global (SUM of all processes <= rps) rather than
    per-process. Pure (no clock/lock/network) so the reservation maths is unit-tested directly."""
    res = sorted(float(t) for t in timestamps)
    if rps is None or rps <= 0:                         # unlimited — record the slot, never sleep
        res.append(now)
        return 0.0, _prune_reservations(res, now, window)
    burst = int(rps)                                    # whole requests allowed to fire inside one window
    if burst >= 1:
        earliest = res[-burst] + window if len(res) >= burst else now
    else:                                               # rps < 1 — even-space at window/rps
        earliest = (res[-1] + window / rps) if res else now
    send_at = max(now, earliest)
    res.append(send_at)
    return max(0.0, send_at - now), _prune_reservations(res, now, window)


class _RateLock:
    """A tiny portable (POSIX + Windows), stdlib advisory file lock over the shared rate-state file.

    The lock is held ONLY for the quick read-modify-write of `rs_http_rate.json` (never across the
    throttle sleep), so contention windows are microseconds. Acquisition is BEST-EFFORT: it contends
    for up to `timeout`, steals a lock older than `stale` (a crashed holder must never wedge a
    legitimate request), and if it still can't get it, proceeds UNLOCKED and degraded rather than
    blocking the request — the same best-effort posture `_save_rate_state` takes. `O_CREAT|O_EXCL`
    file creation is the cross-platform mutex; no fcntl/msvcrt, so it is identical on every OS."""

    def __init__(self, eng: Path, *, timeout: float = RATE_LOCK_TIMEOUT_SEC,
                 stale: float = RATE_LOCK_STALE_SEC):
        self.path = Path(eng) / "runtime" / RATE_LOCK_NAME
        self.timeout = timeout
        self.stale = stale
        self.held = False

    def acquire(self) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            return False
        deadline = time.time() + self.timeout
        while True:
            try:
                fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
                self.held = True
                return True
            except FileExistsError:
                try:                                    # steal a stale lock (crashed holder)
                    if time.time() - os.path.getmtime(self.path) > self.stale:
                        os.unlink(self.path)
                        continue
                except OSError:
                    pass
                if time.time() >= deadline:
                    return False                        # degrade to unlocked, never wedge the request
                time.sleep(0.01)
            except OSError:
                return False

    def release(self) -> None:
        if not self.held:
            return
        self.held = False
        try:
            os.unlink(self.path)
        except OSError:
            pass

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc):
        self.release()
        return False


def _load_rate_state(eng: Path) -> dict:
    try:
        p = Path(eng) / "runtime" / RATE_STATE_NAME
        if p.is_file():
            d = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(d, dict):
                return d
    except Exception:
        pass
    return {"ts": []}


def _save_rate_state(eng: Path, state: dict) -> None:
    try:
        p = Path(eng) / "runtime" / RATE_STATE_NAME
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(state), encoding="utf-8")
    except Exception:
        pass   # pacing is best-effort; a state-write miss must never wedge a legitimate request


# --------------------------------------------------------------------------- redaction + logging
def redact_headers(headers: dict) -> dict:
    return {k: (REDACTED if str(k).lower() in _SECRET_HEADERS else v) for k, v in (headers or {}).items()}


def redact_url(url: str) -> str:
    """Redact secret-looking query-param VALUES in a URL (keys kept, so the log still shows the shape).

    The redacted query is rebuilt by hand (not urlencode) so the ‹redacted› marker stays human-readable
    in the log instead of being percent-encoded."""
    try:
        parts = urlsplit(url)
    except Exception:
        return url
    if not parts.query:
        return url
    red = "&".join(
        f"{k}={REDACTED if _SECRET_PARAM.search(k) else v}"
        for k, v in parse_qsl(parts.query, keep_blank_values=True))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, red, parts.fragment))


def _iso(epoch: float) -> str:
    return _dt.datetime.fromtimestamp(epoch, _dt.timezone.utc).isoformat()


def log_request(eng, entry: dict) -> None:
    """Append one request/response record as JSONL to <engagement>/runtime/http_log.jsonl.

    ``ensure_ascii=False`` so the ‹redacted› marker is written literally. Best-effort: a logging failure
    never fails the request."""
    try:
        p = Path(eng) / "runtime" / LOG_NAME
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


# --------------------------------------------------------------------------- response + opener
class Response:
    """A minimal, dependency-free HTTP response. `status` is None on a transport error (`error` set)."""

    __slots__ = ("status", "headers", "body", "url", "elapsed_ms", "error")

    def __init__(self, status, headers, body, url, elapsed_ms, error=None):
        self.status = status
        self.headers = headers or {}
        self.body = body or b""
        self.url = url
        self.elapsed_ms = elapsed_ms
        self.error = error

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace") if isinstance(self.body, (bytes, bytearray)) else str(self.body)

    def __repr__(self):
        return f"<Response {self.status} {self.url} {len(self.body)}B {self.elapsed_ms}ms>"


def env_proxy() -> str | None:
    """The proxy to route through, from the environment (so requests land in the operator's history)."""
    for k in ("RS_PROXY", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        v = os.environ.get(k)
        if v:
            return v
    return None


def _build_opener(proxy=None, insecure=True, jar=None):
    handlers = [ProxyHandler({"http": proxy, "https": proxy} if proxy else {})]
    ctx = ssl.create_default_context()
    if insecure:                                   # tolerate the interception proxy's CA (-k equivalent)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    handlers.append(HTTPSHandler(context=ctx))
    if jar is not None:
        handlers.append(HTTPCookieProcessor(jar))
    return build_opener(*handlers)


# --------------------------------------------------------------------------- the primitive
def request(method: str, url: str, *, engagement, headers=None, data=None, cookies=None,
            proxy=None, insecure=True, timeout: float = 30.0, rung: str = "direct",
            max_rps: float | None = None, scope: dict | None = None,
            opener=None, log: bool = True, clock=None, sleeper=None,
            probe: bool = False, probe_basis: str | None = None, grants=None) -> Response:
    """Make ONE engagement-aware HTTP request. Enforces scope (raises ScopeError) + write-discipline
    (raises WriteGateError), throttles to the scope rps, routes through the proxy, persists the cookie
    jar, and appends a redacted JSONL log line.

    A MUTATING method (POST/PUT/PATCH/DELETE) is refused unless a covering approval grant exists in
    runtime/approvals.json OR the caller declares `probe=True` with a `probe_basis` (safe-method /
    validation-failing-body / reversed-via-delete_path) — a probe cannot persist state, so it bypasses
    the approval requirement but is LOGGED. Reads (GET/HEAD/OPTIONS) are never gated. See
    write_gate_verdict / write-vs-probe.md. RS_WRITE_GATE=0 disables the gate.

    Importable: `from rs_http import request`. `scope`/`opener`/`clock`/`sleeper`/`grants` are injection
    points (unit tests stub the opener + clock so nothing touches the network)."""
    clock = clock or time.time
    sleeper = sleeper or time.sleep
    eng = Path(engagement)
    scope = scope if scope is not None else load_scope(eng)
    method = method.upper()

    # 1. SCOPE — hard stop before anything touches the wire.
    allowed, reason = scope_verdict(url, scope)
    if not allowed:
        raise ScopeError(f"refusing {method} {url}: {reason}")
    host = host_of_url(url)

    # 1.5 WRITE-DISCIPLINE — a mutating method needs a covering approval grant (or a declared probe).
    # Reads are never gated. Fail-OPEN only in a clearly-safe way: with NO engagement/approvals context
    # present (no runtime dir — a bare call / unit test), mutating methods are NOT gated, so the
    # read-heavy existing call sites are untouched. RS_WRITE_GATE=0 disables it. This runs BEFORE the
    # rate step (which creates runtime/) so the no-context detection is not self-defeated.
    context_present = (eng / "runtime").is_dir()
    gate_grants = grants if grants is not None else (load_grants(eng) if context_present else [])
    w_allowed, w_basis, w_kind = write_gate_verdict(
        method, url, gate_grants, probe=probe, probe_basis=probe_basis,
        context_present=context_present)
    if not w_allowed:
        raise WriteGateError(f"refusing {method} {url}: {w_basis}")

    # 2. RATE — reserve a send-slot in the GLOBAL shared window, then sleep until it. The read-modify-
    # write runs under a cross-process file lock and the reservation is persisted BEFORE the sleep, so
    # K concurrent processes serialise onto distinct slots and the SUM of their rates stays <= the cap
    # (not K x the cap). `--max-rps` already clamped `rps` below the scope number as an extra lower bound.
    rps = resolve_rps(scope, max_rps)
    now = clock()
    lock = _RateLock(eng)
    lock.acquire()                                       # best-effort: proceeds unlocked if it can't get it
    try:
        st = _load_rate_state(eng)
        sleep_s, ts = _throttle_sleep(list(st.get("ts", [])), rps, now)
        st["ts"] = ts
        _save_rate_state(eng, st)
    finally:
        lock.release()
    if sleep_s > 0:
        sleeper(sleep_s)

    # 3. build the request
    body_bytes = data.encode("utf-8") if isinstance(data, str) else data
    hdrs = dict(headers or {})
    if not any(k.lower() == "user-agent" for k in hdrs):
        hdrs["User-Agent"] = DEFAULT_UA
    req = Request(url, data=body_bytes, method=method)
    for k, v in hdrs.items():
        req.add_header(k, v)

    # 4. opener (+ persistent cookie jar for the authed-probe case), unless one was injected
    jar = None
    if opener is None:
        if cookies:
            jar = http.cookiejar.MozillaCookieJar(str(cookies))
            if Path(cookies).is_file():
                try:
                    jar.load(ignore_discard=True, ignore_expires=True)
                except Exception:
                    pass
        opener = _build_opener(proxy=proxy or env_proxy(), insecure=insecure, jar=jar)

    # 5. send + time it
    start = clock()
    status, resp_headers, body, err = None, {}, b"", None
    try:
        r = opener.open(req, timeout=timeout)
        status = getattr(r, "status", None) or r.getcode()
        resp_headers = dict(r.headers.items()) if getattr(r, "headers", None) else {}
        body = r.read()
    except HTTPError as e:                          # a 4xx/5xx is a normal probe result, not an exception
        status = e.code
        resp_headers = dict(e.headers.items()) if getattr(e, "headers", None) else {}
        try:
            body = e.read()
        except Exception:
            body = b""
    except URLError as e:
        err = str(getattr(e, "reason", e))
    except Exception as e:                          # noqa: BLE001 — never let a probe crash the caller
        err = f"{type(e).__name__}: {e}"
    elapsed_ms = round((clock() - start) * 1000, 1)

    if jar is not None and cookies:
        try:
            jar.save(ignore_discard=True, ignore_expires=True)
        except Exception:
            pass

    # 6. LOG — redacted (secrets never reach disk)
    if log:
        log_request(eng, {
            "ts": _iso(now),
            "method": method,
            "url": redact_url(url),
            "host": host,
            "status": status,
            "elapsed_ms": elapsed_ms,
            "req_bytes": len(body_bytes or b""),
            "resp_bytes": len(body or b""),
            "rung": rung,
            "proxied": bool(proxy or env_proxy()),
            "write_gate": w_kind,          # read / probe / approved / disabled / no-context
            "probe": bool(probe),
            "probe_basis": (probe_basis if probe else None),
            "request_headers": redact_headers(hdrs),
            "error": err,
        })

    return Response(status, resp_headers, body, url, elapsed_ms, error=err)


# --------------------------------------------------------------------------- selftest (CI, no network)
def selftest() -> int:
    scope = {"in_scope": {"domains": ["*.example.com", "api.example.com"], "cidrs": ["203.0.113.0/24"],
                          "urls": ["https://portal.acme.io/login"]},
             "out_of_scope": {"domains": ["admin.example.com"], "cidrs": ["203.0.113.200/29"]},
             "rules": {"rate_limit_rps": 5}}
    # scope matching
    assert classify("app.example.com", scope) == "in"
    assert classify("admin.example.com", scope) == "out"      # explicit exclude wins over *.example.com
    assert classify("evil.com", scope) == "unknown"
    assert classify("203.0.113.10", scope) == "in"
    assert classify("203.0.113.201", scope) == "out"
    assert classify("portal.acme.io", scope) == "in"          # host from in_scope.urls
    assert scope_verdict("https://admin.example.com/x", scope)[0] is False
    assert scope_verdict("https://app.example.com/x", scope)[0] is True
    # rps resolution + throttle
    assert resolve_rps(scope) == 5.0
    assert resolve_rps({"rules": {}}) == DEFAULT_RPS
    sleep, ts = _throttle_sleep([0.1, 0.3, 0.5, 0.7, 0.9], 5, 1.0)
    assert sleep > 0 and len(ts) >= 1, "a full window must force a positive sleep"
    sleep0, _ = _throttle_sleep([0.9], 5, 1.0)
    assert sleep0 == 0.0, "an under-budget window must not sleep"
    # GLOBAL cap: chaining reservations (as concurrent processes would, each reserving under the lock
    # then persisting its slot BEFORE sleeping) keeps the SUM <= rps — at most `rps` sends per window.
    rps, win, state, sends = 2, RATE_WINDOW_SEC, [], []
    for now in (0.0, 0.0, 0.0, 0.0, 0.0, 0.0):          # 6 "processes" all arriving at once, rps=2
        sl, state = _throttle_sleep(list(state), rps, now, win)
        sends.append(now + sl)                          # the reserved send time
    sends.sort()
    assert all(sends[i + rps] - sends[i] >= win - 1e-9 for i in range(len(sends) - rps)), \
        "any rps+1 consecutive reserved sends must span >= one window (global cap holds)"
    assert sends[0] == sends[1] == 0.0 and sends[-1] >= 2 * win - 1e-9, \
        "an initial burst of rps is allowed, then the batch is spaced by the window"
    # redaction
    rh = redact_headers({"Authorization": "Bearer abc", "Accept": "application/json"})
    assert rh["Authorization"] == REDACTED and rh["Accept"] == "application/json"
    assert "SECR3T" not in redact_url("https://app.example.com/cb?token=SECR3T&page=2")
    assert "page=2" in redact_url("https://app.example.com/cb?token=SECR3T&page=2")
    # write-gate (pure verdict logic — no network)
    url = "https://app.example.com/api/comments"
    assert write_gate_verdict("GET", url, [])[0] is True, "a read is never gated"
    assert write_gate_verdict("HEAD", url, [])[0] is True
    assert write_gate_verdict("POST", url, [])[0] is False, "a mutating request with no grant is refused"
    # a covering production-write grant allows it
    cover = {"scope_granted": "POST a benign marker to app.example.com/api/comments",
             "write_class": "production-write"}
    assert write_gate_verdict("POST", url, [cover])[0] is True, "a covering grant allows the write"
    # a grant that names a DIFFERENT endpoint must NOT be stretched to this one (incident #1)
    other = {"scope_granted": "POST to app.example.com/api/profile", "write_class": "production-write"}
    assert write_gate_verdict("POST", url, [other])[0] is False, "a grant can't be stretched to an uncovered endpoint"
    # a grant for the collection endpoint DOES cover a sub-resource under it (dynamic id)
    assert write_gate_verdict("POST", "https://app.example.com/api/comments/42", [cover])[0] is True, \
        "a parent-endpoint grant covers its sub-resource"
    assert write_gate_verdict("POST", "https://app.example.com/api/profiles/42", [cover])[0] is False, \
        "but not a different endpoint tree"
    # a reversible-self-write grant WITHOUT a delete_path is invalid → refused
    norev = {"scope_granted": "POST to app.example.com/api/comments", "write_class": "reversible-self-write"}
    assert write_gate_verdict("POST", url, [norev])[0] is False, "reversible-self-write with no delete_path is refused"
    rev = dict(norev, delete_path="DELETE /api/comments/{id}")
    assert write_gate_verdict("POST", url, [rev])[0] is True, "reversible-self-write WITH delete_path is allowed"
    # a declared probe + valid basis bypasses the approval requirement (and is logged)
    ok, basis, kind = write_gate_verdict("POST", url, [], probe=True, probe_basis="validation-failing-body")
    assert ok is True and kind == "probe" and "validation-failing-body" in basis
    assert write_gate_verdict("POST", url, [], probe=True, probe_basis="bogus")[0] is False, "an invalid probe_basis is refused"
    assert write_gate_verdict("POST", url, [], context_present=False)[0] is True, "no-context reads/writes are not gated"
    import os as _os
    _prev = _os.environ.get(WRITE_GATE_ENV)
    _os.environ[WRITE_GATE_ENV] = "0"
    try:
        assert write_gate_verdict("POST", url, [])[0] is True, "RS_WRITE_GATE=0 disables the gate"
    finally:
        if _prev is None:
            _os.environ.pop(WRITE_GATE_ENV, None)
        else:
            _os.environ[WRITE_GATE_ENV] = _prev
    print("rs_http.py selftest: OK (scope matching, global rps slot-reservation, redaction, write-gate)")
    return 0


# --------------------------------------------------------------------------- CLI
def _parse_headers(items) -> dict:
    out = {}
    for it in items or []:
        if ":" not in it:
            raise SystemExit(f"[!] bad header (want 'Name: value'): {it!r}")
        k, _, v = it.partition(":")
        out[k.strip()] = v.strip()
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="rs_http.py",
        description="Engagement-aware HTTP primitive: scope-checked, rate-throttled, proxied, "
                    "cookie-persisting, with a redacted JSONL log. Use this instead of re-rolling "
                    "urllib+proxy+login boilerplate in a bespoke probe.",
        epilog="examples:\n"
               "  rs_http.py --engagement engagements/acme-2026-10 GET https://app.acme.com/me \\\n"
               "      -H 'Authorization: Bearer T' --cookies acme.jar\n"
               "  RS_PROXY=http://127.0.0.1:8080 rs_http.py --engagement <dir> POST \\\n"
               "      https://api.acme.com/login --data 'u=a&p=b' --cookies acme.jar\n"
               "  rs_http.py --selftest",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--engagement", help="engagement dir (reads scope.yaml / runtime/scope.json)")
    ap.add_argument("method", nargs="?", help="HTTP method (GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS)")
    ap.add_argument("url", nargs="?", help="absolute target URL (must be in the engagement scope)")
    ap.add_argument("-H", "--header", action="append", default=[], metavar="'Name: value'",
                    help="request header (repeatable)")
    ap.add_argument("-d", "--data", help="request body (string); implies a body-bearing method")
    ap.add_argument("--data-file", help="read the request body from this file")
    ap.add_argument("--cookies", help="persistent cookie-jar file (Mozilla format) — load + save")
    ap.add_argument("--proxy", help="proxy URL (else RS_PROXY / HTTPS_PROXY / HTTP_PROXY)")
    ap.add_argument("-k", "--insecure", action="store_true",
                    help="tolerate an untrusted TLS cert (default ON; the proxy CA) — kept for clarity")
    ap.add_argument("--verify", action="store_true", help="REQUIRE a valid TLS cert (turn tolerance off)")
    ap.add_argument("--timeout", type=float, default=30.0, help="per-request timeout seconds (default 30)")
    ap.add_argument("--rung", default="direct", help="anti-automation ladder rung this request used "
                    "(recorded in the log; default 'direct')")
    ap.add_argument("--max-rps", type=float, help="clamp the throttle below the scope's rate_limit_rps")
    ap.add_argument("--probe", action="store_true",
                    help="declare this mutating request a PROBE that cannot persist state (write-vs-probe.md) "
                         "— bypasses the approval requirement but is logged; requires --probe-basis")
    ap.add_argument("--probe-basis", choices=sorted(PROBE_BASES),
                    help="why the probe cannot persist state (required with --probe)")
    ap.add_argument("-i", "--include", action="store_true", help="print response headers before the body")
    ap.add_argument("--selftest", action="store_true", help="run the no-network self-test (CI)")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.engagement or not args.method or not args.url:
        ap.error("need --engagement METHOD URL (or --selftest)")
    eng = Path(args.engagement)
    if not eng.is_dir():
        ap.error(f"engagement dir not found: {eng}")

    data = args.data
    if args.data_file:
        data = Path(args.data_file).read_bytes()

    if args.probe and not args.probe_basis:
        ap.error("--probe requires --probe-basis (safe-method / validation-failing-body / reversed-via-delete_path)")

    try:
        r = request(args.method, args.url, engagement=eng,
                    headers=_parse_headers(args.header), data=data, cookies=args.cookies,
                    proxy=args.proxy, insecure=(not args.verify), timeout=args.timeout,
                    rung=args.rung, max_rps=args.max_rps,
                    probe=args.probe, probe_basis=args.probe_basis)
    except ScopeError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2
    except WriteGateError as e:
        # Same altitude as a scope refusal: framed as engagement/RoE policy so the agent re-plans
        # (record a covering grant, or declare a probe) instead of trying to bypass it.
        print(f"[!] {e}", file=sys.stderr)
        print("[i] write-discipline (NOT a target defense): record a covering approval grant in "
              "runtime/approvals.json (roe-gate.md §2), or re-run with --probe --probe-basis if it "
              "genuinely cannot persist state.", file=sys.stderr)
        return 2

    summary = (f"{r.status if r.status is not None else 'ERR'} {args.method} {args.url}  "
               f"{r.elapsed_ms}ms  {len(r.body)}B  [rung={args.rung}]")
    print(summary, file=sys.stderr)
    if r.error:
        print(f"[!] transport error: {r.error}", file=sys.stderr)
    if args.include:
        for k, v in r.headers.items():
            print(f"{k}: {v}", file=sys.stderr)
    sys.stdout.buffer.write(r.body if isinstance(r.body, (bytes, bytearray)) else str(r.body).encode())
    return 0 if (r.status is not None and not r.error) else 1


if __name__ == "__main__":
    raise SystemExit(main())
