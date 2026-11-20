#!/usr/bin/env python3
"""
surface.py -- the surface-coverage ledger (recall fix #5, the capstone).

Category coverage (coverage.py) proves which vuln CLASSES ran. It cannot see how much of the real
attack SURFACE each class was tested against: recon can discover 20 injectable params and the SQLi
executor test 2, and the category ledger still reads "sqli: attempted, 0 findings" — a clean-looking
result hiding 18 untested params. That surface gap is the single biggest recall leak, and it is
invisible to every category-level gate.

This ledger makes "tested vs merely discovered" a first-class, visible, GATED state per surface element
(endpoint / param / identity / form / api-operation / sink / header / upload / auth-flow). A surface
discovered but never tested (and not skipped with a reason) is a recall gap:

The SAME mechanism serves the white-box / source-code audit: when source access is granted, the
`code-audit` executor can finish having only looked at the leads `source-audit` happened to route, silently
missing entry points / sinks / files no lead covered. So the ledger also models a SOURCE surface —
`entry-point` (routes/handlers/CLI/jobs/queue-consumers/webhooks from app_model.json), `source-lead`
(each source_context.json candidate / structural fact / chain candidate), and `high-risk-file` (a file
hosting any of that surface) — all routed to the `code-audit` consumer. `load_source_surfaces(eng)` reads
those two artifacts; `validate(..., routed_to="code-audit")` scopes the gate to one consumer's slice so a
white-box executor can prove IT closed the whole source surface without being blocked by a sibling's
still-pending black-box recon surface in the same shared ledger.
  - the recall-audit altitude reports it as an `untested-surface` miss (concrete, not inferred);
  - once a report exists, verify_completion.py HARD-FAILS on it (like a pending category).

This upgrades the escalation ladder (#3) and the recall audit (#4) from inference over category signals
to FACT over enumerated surface: "this exact param was discovered and never fed to an executor."

Pure logic for the decision paths (route / validate / plan_from_items) so they unit-test with no
network; a best-effort `load_recon_surfaces(eng)` reads the usual feeder artifacts. Stdlib only.
`python scripts/surface.py --selftest`.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, parse_qsl

# atomic_write: one shared helper for ledger writes. scripts/ is on sys.path for a direct run and for
# the validate.py / verify_completion spec-loads; fall back to a path-load when it is not (e.g. the
# _contract tests load this module by path directly).
try:
    from atomicio import atomic_write
except ImportError:  # pragma: no cover - only hit under path-based loading without scripts/ on sys.path
    import importlib.util as _ilu
    _aspec = _ilu.spec_from_file_location("atomicio", str(Path(__file__).resolve().parent / "atomicio.py"))
    _amod = _ilu.module_from_spec(_aspec)
    _aspec.loader.exec_module(_amod)
    atomic_write = _amod.atomic_write


# --- concurrent-writer safety -------------------------------------------------------------------- #
# The hunt fans out as CONCURRENT subagents that mark / re-plan this ledger simultaneously. `atomic_write`
# stops a reader seeing a torn file, but two writers that each read-then-write still clobber each other
# (last-write-wins). A per-file advisory lock serializes the read-modify-write so every concurrent
# mark / merge survives. (Mirror of coverage.py's lock; duplicated to keep these CLI scripts standalone.)
class _FileLock:
    """Best-effort cross-process advisory lock via an exclusive lock file (stdlib only; no fcntl/msvcrt,
    so Windows + Linux/WSL behave identically). Spins up to ``timeout``; a lock older than ``stale`` is
    treated as abandoned and broken. If it still can't acquire by the deadline it proceeds anyway
    (degraded last-write-wins) rather than deadlock the hunt — ``atomic_write`` keeps the file un-torn."""

    def __init__(self, target, *, timeout: float = 30.0, poll: float = 0.05, stale: float = 120.0):
        self._path = str(target) + ".lock"
        self._timeout, self._poll, self._stale = timeout, poll, stale
        self._held = False

    def __enter__(self):
        deadline = time.monotonic() + self._timeout
        while True:
            try:
                fd = os.open(self._path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                try:
                    if time.time() - os.path.getmtime(self._path) > self._stale:
                        os.unlink(self._path)   # break an abandoned lock
                        continue
                except OSError:
                    pass
                if time.monotonic() >= deadline:
                    return self                 # proceed un-locked rather than block the whole hunt
                time.sleep(self._poll)
                continue
            try:
                os.write(fd, str(os.getpid()).encode("ascii", "replace"))
            finally:
                os.close(fd)
            self._held = True
            return self

    def __exit__(self, *exc):
        if self._held:
            try:
                os.unlink(self._path)
            except OSError:
                pass
            self._held = False
        return False


LEDGER_NAME = "surface_ledger.json"
_OPEN_STATUS = "discovered"            # enumerated but never tested == a gap at close
_NEED_REASON = {"skipped", "n/a"}
_MARK_STATUSES = {"discovered", "tested", "skipped", "n/a"}

# Coarse kind -> the category ids whose executors SHOULD consume a surface of that kind. Not the fine
# signal routing (routing-map.json does that per-signal); this answers "did SOME relevant executor test
# this element at all". Keep ids aligned with routing-map category ids.
KIND_ROUTES = {
    "endpoint":      ["exposed-surface"],
    "param":         ["xss", "sqli", "nosql-injection", "injection", "ssrf", "authz", "open-redirect", "file"],
    "identity":      ["authz", "api"],
    "form":          ["xss", "sqli", "csrf", "auth"],
    "api-operation": ["api", "authz"],
    "sink":          ["injection", "ssti", "command-injection", "deserialization", "xss"],
    "header":        ["host-header", "security-headers"],
    "upload":        ["file", "upload-rce"],
    "auth-flow":     ["auth", "jwt", "oauth"],
    # white-box / source-code audit surface — a single executor (code-audit) is the consumer that PROVES
    # each of these by reading the real code path, so they route to it alone (not the black-box classes).
    "entry-point":   ["code-audit"],   # route/handler/CLI/job/queue-consumer/webhook from app_model.json
    "source-lead":   ["code-audit"],   # a source_context.json candidate / structural fact / chain candidate
    "high-risk-file": ["code-audit"],  # a file hosting attack surface (sink / entry point / authz-sensitive)
    # two FIRST-CLASS enumerated white-box surfaces grep/taint cannot see (no pattern asserts "no lock" or
    # "no authz annotation") — enumerated from the app model, each PROVEN by the code-audit executor:
    "state-op":      ["code-audit"],   # a state-changing op + the invariant it must hold (single-use / limit /
                                       #   quota / stock / price / ownership / idempotency) — TOCTOU/double-spend pass
    "authz-route":   ["code-audit"],   # a route/handler x its required privilege (one authorization-matrix cell)
}

# The CLOSED set of surface kinds — identical to surface_ledger.schema.json $defs/surface/kind/enum.
# A discovered element whose kind is NOT one of these is a malformed coordination record (e.g. an inbox
# `content` surface): it is REJECTED at ingest, never added to the ledger as `n/a`, where an invalid kind
# would masquerade as an accounted-for element and a gate would read it as clean.
VALID_KINDS = frozenset(KIND_ROUTES)


def route_surface(kind: str) -> list:
    """Category ids a surface of this kind should be tested by (deterministic)."""
    return list(KIND_ROUTES.get(kind, []))


def partition_items(items):
    """Split normalized discovered items into (valid, rejected). A valid item has a non-empty value and a
    kind in the closed surface-kind enum; everything else is rejected WITH a reason, so a malformed
    coordination record is quarantined instead of silently entering the ledger. Pure (no I/O)."""
    valid, rejected = [], []
    for it in items or []:
        kind = (it or {}).get("kind")
        value = str((it or {}).get("value", "")).strip()
        if not kind or not value:
            rejected.append({**(it or {}), "_reject_reason": "missing kind or value"})
        elif kind not in VALID_KINDS:
            rejected.append({**it, "_reject_reason": f"kind {kind!r} is not a surface-ledger kind "
                                                     f"({', '.join(sorted(VALID_KINDS))})"})
        else:
            valid.append(it)
    return valid, rejected


def _sid(kind: str, value: str) -> str:
    return f"{kind}:" + hashlib.sha1(f"{kind}|{value}".encode()).hexdigest()[:10]


def plan_from_items(engagement: str, items, warn: bool = True) -> dict:
    """Build a fresh ledger from normalized discovered items [{kind,value,discovered_by?}, ...].
    Every VALID element starts `discovered` (routes computed) or `n/a` when it routes to no category.
    An out-of-enum kind is REJECTED (not added as n/a) and, when `warn`, announced loudly on stderr."""
    valid, rejected = partition_items(items)
    if rejected and warn:
        for r in rejected:
            print(f"[surface] REJECTED invalid surface record: kind={r.get('kind')!r} "
                  f"value={str(r.get('value',''))[:60]!r} — {r['_reject_reason']}", file=sys.stderr)
    seen, surfaces = set(), []
    for it in valid:
        kind = it.get("kind")
        value = str(it.get("value", "")).strip()
        sid = _sid(kind, value)
        if sid in seen:
            continue
        seen.add(sid)
        routes = route_surface(kind)
        surfaces.append({
            "id": sid, "kind": kind, "value": value,
            "discovered_by": it.get("discovered_by", "recon"),
            "routed_to": routes,
            "status": "discovered" if routes else "n/a",
            "reason": "" if routes else "routes to no in-scope category",
        })
    return {"engagement": engagement,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "surfaces": surfaces}


def merge_plan(existing: dict, items) -> dict:
    """Idempotent re-plan (universal emission): keep every element already in the ledger AND its
    progress (`status`/`consumed_by`/`reason`), and append only genuinely NEW discovered elements.

    This is what lets recon emit the ledger universally and re-run `--plan` safely as late feeders
    (authz-context identities, js-analysis) and the re-convergence loop add surface, without clobbering
    a `tested`/`skipped` mark. A fresh `plan_from_items` would reset every element to `discovered`."""
    fresh = plan_from_items(existing.get("engagement", ""), items)
    have = {s["id"] for s in existing.get("surfaces", [])}
    added = 0
    for s in fresh["surfaces"]:
        if s["id"] not in have:
            existing.setdefault("surfaces", []).append(s)
            have.add(s["id"])
            added += 1
    existing["generated_at"] = fresh["generated_at"]
    existing["_last_merge_added"] = added
    return existing


def _routed_subset(surfaces, routed_to):
    """The surfaces routed to a given consumer (e.g. 'code-audit'), or all when routed_to is None.
    Lets a single executor gate its OWN slice of a shared ledger without being blocked by a sibling's
    still-pending surface. Pure (no I/O)."""
    if routed_to is None:
        return surfaces
    return [s for s in surfaces if routed_to in (s.get("routed_to") or [])]


def validate(led: dict, strict: bool = False, routed_to: str | None = None):
    """Return (ok, lines, msgs). ok=False => a surface gap (discovered-but-untested, or skipped w/o reason).

    `routed_to` scopes the check to one consumer category (e.g. 'code-audit' for the white-box audit):
    only elements that route to it are gated, so a white-box executor can prove it closed the whole
    SOURCE surface (entry-points / source-leads / high-risk-files) independently of a sibling's untested
    black-box recon surface living in the same shared ledger."""
    errors, lines = [], []
    surfaces = led.get("surfaces", [])
    if not isinstance(surfaces, list):
        return False, [], ["surfaces is not a list"]
    surfaces = _routed_subset(surfaces, routed_to)
    scope = f" routed to {routed_to}" if routed_to else ""
    from collections import Counter
    tally = Counter(s.get("status") for s in surfaces)
    for s in surfaces:
        st = s.get("status")
        if st == _OPEN_STATUS and s.get("routed_to"):
            errors.append(f"surface {s.get('kind')}:{s.get('value')!r} discovered but NEVER tested "
                          f"(routes to {', '.join(s.get('routed_to', []))}) — untested surface")
        if st in _NEED_REASON and not (s.get("reason") or "").strip():
            errors.append(f"surface {s.get('kind')}:{s.get('value')!r} is '{st}' without a reason")
    lines.append((f"surfaces{scope}: " + ", ".join(f"{k}={tally[k]}" for k in sorted(tally))) if tally
                 else f"surfaces{scope}: (none enumerated)")
    # empty-but-present ledger isn't automatically a pass under --strict (feeders enumerated nothing?)
    if strict and not surfaces:
        errors.append(f"surface ledger has no elements{scope} — the inventory enumerated nothing "
                      "(did the feeders / the white-box surface-inventory step run?)")
    return (not errors), lines, errors


def surface_gaps(led: dict, routed_to: str | None = None) -> list:
    """Ranked recall gaps for the recall-audit altitude: each discovered-but-untested routed surface.
    `routed_to` scopes it to one consumer (e.g. 'code-audit')."""
    gaps = []
    for s in _routed_subset(led.get("surfaces", []), routed_to):
        if s.get("status") == _OPEN_STATUS and s.get("routed_to"):
            gaps.append({"category": (s.get("routed_to") or [None])[0], "type": "untested-surface",
                         "severity": "high",
                         "detail": f"{s.get('kind')} {s.get('value')!r} discovered by "
                                   f"{s.get('discovered_by','recon')} but fed to no executor",
                         "suggested_action": "route it to " + ", ".join(s.get("routed_to", [])) + " and test it"})
    return gaps


def coverage_stats(led: dict, routed_to: str | None = None) -> dict:
    """Honest coverage figures over the ledger (optionally one consumer's slice). `closed` = an element
    that was tested / skipped-with-reason / n-a; `open_gaps` = discovered-but-still-routed (the recall
    gaps). `pct` is closed/tracked as a whole percent — the honest coverage figure a white-box audit
    reports, and what makes PARTIAL coverage explicit (pct < 100 with open_gaps named) rather than a
    partial pass dressed up as complete. Pure (no I/O)."""
    from collections import Counter
    surfaces = _routed_subset(led.get("surfaces", []), routed_to)
    tally = Counter(s.get("status") for s in surfaces)
    total = len(surfaces)
    closed = tally.get("tested", 0) + tally.get("skipped", 0) + tally.get("n/a", 0)
    open_gaps = sum(1 for s in surfaces if s.get("status") == _OPEN_STATUS and s.get("routed_to"))
    return {"routed_to": routed_to, "total": total, "by_status": dict(tally),
            "closed": closed, "open_gaps": open_gaps,
            "pct": (round(100 * closed / total) if total else 100)}


# ------------------------------- best-effort recon readers ------------------------------- #
def _read_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _iter_jsonl(p: Path):
    """Yield each parseable JSON object from a .jsonl file (malformed lines skipped)."""
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except Exception:
            continue


def _path_and_params(url) -> tuple:
    """(path, [query-param names]) from a URL/endpoint, tolerant of a bare path. The path drops any
    scheme+host and query string so it is a stable attribution key: '/_next/image?url=x&w=64' and
    'https://h/_next/image?url=y' both yield ('/_next/image', ['url', ...])."""
    s = str(url or "").strip()
    if not s:
        return "", []
    parts = urlsplit(s)
    path = parts.path if (parts.scheme or parts.netloc) else (s.split("?", 1)[0] or s)
    names, seen = [], set()
    for k, _v in parse_qsl(parts.query, keep_blank_values=True):
        if k and k not in seen:
            seen.add(k)
            names.append(k)
    return path, names


def _attr_param(name, endpoint) -> str:
    """A param value carrying its endpoint attribution — 'url@/_next/image' — so the SAME param name
    on two different endpoints is TWO distinct surface elements (not collapsed into one tested-once row).
    Falls back to the bare name when no endpoint is known."""
    nm = str(name or "").strip()
    if not endpoint:
        return nm
    path, _ = _path_and_params(endpoint)
    return f"{nm}@{path}" if path else nm


# A content-kind discovery (sitemap/robots/API schema) is NOT a testable surface element, so it never
# enters the ledger; instead it ROUTES BACK to content-discovery for URL/object-ref extraction (fix #5).
FOLLOWUP_ROUTES = {"content": "content-discovery"}


def followup_route(kind: str):
    """The recon FEEDER a non-testable 'follow-up' kind (e.g. `content`) routes to, or None."""
    return FOLLOWUP_ROUTES.get(kind)


def content_reroutes(items) -> list:
    """Directives for content-kind discoveries (sitemaps/robots/API schemas): route each BACK to
    content-discovery to extract the URLs + object references it contains, instead of dropping it as an
    out-of-enum surface (where a sitemap of 200 endpoints would silently vanish). Pure (no I/O)."""
    out = []
    for it in items or []:
        kind = (it or {}).get("kind")
        value = str((it or {}).get("value", "")).strip()
        route = followup_route(kind)
        if route and value:
            out.append({"kind": kind, "value": value,
                        "discovered_by": (it or {}).get("discovered_by", "recon"),
                        "route_to": route,
                        "action": "extract URLs + object references"})
    return out


def load_recon_surfaces(eng: Path) -> list:
    """Enumerate surface items from the usual feeder artifacts (best-effort; missing = skipped).

    Reads the REAL on-disk layouts the feeders actually write — notably js-analysis'
    `out/<site>/findings/*.jsonl` tree (NOT a flat `js-analysis/*.jsonl`, which never existed), and
    content-discovery's `endpoints.txt` as well as `params*.txt` — plus loaders for the surface kinds
    that were declared but never populated (sink/header/form/upload/auth-flow). Params carry their
    endpoint attribution (`name@/path`) so the same name on two endpoints is two distinct elements."""
    items = []

    def add(kind, value, by):
        if value is None:
            return
        v = str(value).strip()
        if v:
            items.append({"kind": kind, "value": v, "discovered_by": by})

    # --- host-discovery: live hosts (endpoint) + api endpoints (api-operation) ---
    hd = _read_json(eng / "host-discovery" / "host_discovery.json") or {}
    for h in hd.get("live_hosts", []) or []:
        if isinstance(h, dict) and h.get("url"):
            add("endpoint", h["url"], "host-discovery")
        elif isinstance(h, str):
            add("endpoint", h, "host-discovery")
    for ep in hd.get("api_endpoints", []) or []:
        add("api-operation", ep.get("path") if isinstance(ep, dict) else ep, "host-discovery")

    # --- authz-context / api-context: test identities ---
    az = _read_json(eng / "authz-context" / "authz_context.json") or {}
    for ident in az.get("identities", []) or []:
        if isinstance(ident, dict):
            add("identity", ident.get("label") or ident.get("role") or ident.get("email"), "authz-context")
        else:
            add("identity", ident, "authz-context")

    # --- content-discovery: endpoints.txt (NEW) + params*.txt + the consolidated content.json ---
    cd = eng / "content-discovery"
    if cd.is_dir():
        epf = cd / "endpoints.txt"
        if epf.is_file():
            for line in epf.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                path, qparams = _path_and_params(line)
                add("endpoint", path or line, "content-discovery")
                for pn in qparams:
                    add("param", _attr_param(pn, path or line), "content-discovery")
        for pf in cd.glob("params*.txt"):
            for line in pf.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    add("param", line, "content-discovery")
        cj = _read_json(cd / "content.json") or {}
        for r in cj.get("routes", []) or []:
            if not isinstance(r, dict):
                continue
            rpath = r.get("path")
            path, qparams = _path_and_params(rpath or "")
            add("endpoint", path or rpath, "content-discovery")
            if str(r.get("type", "")).lower() == "form":
                add("form", path or rpath, "content-discovery")
            for pn in list(r.get("params") or []) + qparams:
                add("param", _attr_param(pn, path or rpath), "content-discovery")
        for cls, sinks in (cj.get("notable_sinks") or {}).items():
            for s in sinks or []:
                add("sink", f"{s} [{cls}]", "content-discovery")

    # --- js-analysis: the REAL out/<site>/findings/*.jsonl tree (endpoints/params/gadgets) ---
    for base in (eng / "js-analysis", eng):
        for findings_dir in sorted(base.glob("out/*/findings")):
            if not findings_dir.is_dir():
                continue
            for o in _iter_jsonl(findings_dir / "endpoints.jsonl"):
                v = (o.get("url") or o.get("path")) if isinstance(o, dict) else o
                if not v:
                    continue
                path, qparams = _path_and_params(v)
                add("endpoint", path or v, "js-analysis")
                for pn in qparams:
                    add("param", _attr_param(pn, path or v), "js-analysis")
            for o in _iter_jsonl(findings_dir / "params.jsonl"):
                if isinstance(o, dict):
                    name = o.get("name") or o.get("param")
                    carrier = (o.get("kind") or "").lower()
                    endpoint = o.get("endpoint") or o.get("url") or o.get("path")
                else:
                    name, carrier, endpoint = o, "", None
                if not name:
                    continue
                if carrier == "header":
                    add("header", name, "js-analysis")
                else:
                    add("param", _attr_param(name, endpoint), "js-analysis")
            for o in _iter_jsonl(findings_dir / "gadgets.jsonl"):
                if isinstance(o, dict):
                    sink = o.get("sink") or o.get("snippet")
                    loc, ln = o.get("source_file"), o.get("line")
                    if sink and loc:
                        add("sink", f"{sink} @ {loc}:{ln}" if ln is not None else f"{sink} @ {loc}", "js-analysis")
                    else:
                        add("sink", sink, "js-analysis")
                elif o:
                    add("sink", o, "js-analysis")

    # --- auth-context: auth flows (auth-flow) ---
    ac = _read_json(eng / "auth-context" / "auth_context.json") or {}
    for fl in ac.get("flows", []) or []:
        if isinstance(fl, dict):
            k, fid = fl.get("kind"), fl.get("id")
            add("auth-flow", f"{k}:{fid}" if (k and fid and k != fid) else (fid or k), "auth-context")
        else:
            add("auth-flow", fl, "auth-context")

    # --- file-context: upload endpoints (upload) ---
    fc = _read_json(eng / "file-context" / "file_context.json") or {}
    for t in fc.get("targets", []) or []:
        if isinstance(t, dict) and (t.get("kind") or "") == "upload":
            add("upload", t.get("endpoint"), "file-context")

    return items


def _loc(file, line) -> str:
    """A stable 'file:line' (or bare 'file') anchor for a source element. Deterministic so --plan ids
    are stable across re-runs (merge_plan stays idempotent)."""
    f = str(file or "").strip()
    if not f:
        return ""
    return f"{f}:{line}" if line not in (None, "") else f


def load_source_surfaces(eng: Path) -> list:
    """Enumerate the WHITE-BOX / source surface for a code-audit engagement (best-effort; missing = skipped).

    This is the source-access counterpart of load_recon_surfaces: it reads the two white-box artifacts
      * <eng>/code-audit/app_model.json   — the app model (entry points + privileged ops + state_ops +
        authz_routes)
      * <eng>/source-audit/source_context.json — the routed candidate map (sinks/leads + structural facts
        + chain candidates)
    and enumerates EVERY entry point, EVERY source-audit lead, EVERY high-risk file (a file that hosts any of
    that surface), EVERY state-changing operation + the invariant it must hold (`state-op`), and EVERY route x
    required-privilege cell (`authz-route`) — the last two being FIRST-CLASS enumerated surfaces grep cannot
    assert ("no lock" / "no authz annotation") — so none can be silently skipped. Values carry the element's
    stable id / location so
    the SAME element is one row across re-plans. All route to the `code-audit` consumer. The high-risk-file
    set is derived FROM the leads/entry points (not from the whole tree), so a huge repo (29k files) yields
    a bounded, risk-prioritized file inventory — never one row per repo file."""
    items = []
    hr_files = set()  # distinct files that host attack surface -> high-risk-file elements

    def add(kind, value, by):
        v = str(value or "").strip()
        if v:
            items.append({"kind": kind, "value": v, "discovered_by": by})

    def note_file(f):
        f = str(f or "").strip()
        if f:
            hr_files.add(f)

    # --- app_model.json: entry points (routes/handlers/CLI/jobs/queue-consumers/webhooks) + privileged ops ---
    am = _read_json(eng / "code-audit" / "app_model.json") or {}
    # Whether the app model actually PROVIDES each typed surface. When it is thin/absent for a type, the
    # structural-fact loop below derives that typed surface from source_context.structural[] instead, so a
    # white-box run whose app_model was never written still gets entry-point / authz-route / state-op
    # coverage (not just generic source-leads) — "(+ source_context.structural[] when app_model is thin)".
    have_entry = bool(am.get("entry_points"))
    have_state = bool(am.get("state_ops"))
    have_authz = bool(am.get("authz_routes"))
    for ep in am.get("entry_points", []) or []:
        if not isinstance(ep, dict):
            add("entry-point", ep, "code-audit:app-model")
            continue
        label = (ep.get("symbol") or f"{ep.get('method','')} {ep.get('route','')}".strip()
                 or ep.get("route") or ep.get("kind") or "entry")
        loc = _loc(ep.get("file"), ep.get("line"))
        add("entry-point", f"{label} @ {loc}" if loc else str(label), "code-audit:app-model")
        note_file(ep.get("file"))
    for po in am.get("privileged_ops", []) or []:
        if not isinstance(po, dict):
            continue
        loc = _loc(po.get("file"), po.get("line"))
        op = po.get("op") or "privileged-op"
        add("source-lead", f"priv-op {op} @ {loc}" if loc else f"priv-op {op}", "code-audit:app-model")
        note_file(po.get("file"))
    # --- state-changing operations + the invariant each must hold (business-logic / concurrency pass) ---
    # A FIRST-CLASS enumerated surface: grep cannot assert "this check-then-act has no lock". The executor
    # enumerates each state-changing op and its invariant (single-use / redemption-or-usage limit / quota /
    # stock / price-integrity / ownership / idempotency / monotonic counter) into app_model.state_ops, so EACH
    # is a ledger row to prove against TOCTOU / double-spend / a client-trusted value not re-derived server-side.
    for so in am.get("state_ops", []) or []:
        if not isinstance(so, dict):
            add("state-op", so, "code-audit:app-model")
            continue
        loc = _loc(so.get("file"), so.get("line"))
        op = so.get("op") or so.get("operation") or "state-op"
        inv = so.get("invariant") or so.get("invariants") or "?"
        add("state-op", f"{op} [inv: {inv}] @ {loc}" if loc else f"{op} [inv: {inv}]", "code-audit:app-model")
        note_file(so.get("file"))
    # --- authorization matrix: every route/handler x its required privilege (one cell each) ---
    # A FIRST-CLASS enumerated surface: grep cannot assert "this route has NO authz annotation". The executor
    # enumerates the route x required-privilege matrix (incl. framework/default-based ACL) into
    # app_model.authz_routes, so EACH state-changing / sensitive cell is a ledger row to prove carries an
    # effective guard — including a route that bypasses a central authz backstop (service / queue / raw SQL).
    for ar in am.get("authz_routes", []) or []:
        if not isinstance(ar, dict):
            add("authz-route", ar, "code-audit:app-model")
            continue
        loc = _loc(ar.get("file"), ar.get("line"))
        route = ar.get("route") or ar.get("path") or ar.get("handler") or "route"
        method = (ar.get("method") or "").strip()
        label = (f"{method} {route}").strip()
        priv = (ar.get("required_privilege") or ar.get("privilege") or ar.get("required_role")
                or ar.get("role") or "?")
        add("authz-route", f"{label} [priv: {priv}] @ {loc}" if loc else f"{label} [priv: {priv}]",
            "code-audit:app-model")
        note_file(ar.get("file"))
    # files code-audit itself flags high-risk during modeling (crypto / deserializer / auth middleware)
    # that no source-audit lead points at — declared in app_model so a re-plan folds them in.
    for hrf in am.get("high_risk_files", []) or []:
        note_file(hrf.get("file") or hrf.get("path") if isinstance(hrf, dict) else hrf)

    # --- source_context.json: candidates (sa-*) + structural facts (sf-*) + chain candidates (scc-*) ---
    sc = _read_json(eng / "source-audit" / "source_context.json") or {}
    for c in sc.get("candidates", []) or []:
        if not isinstance(c, dict):
            continue
        loc = _loc(c.get("file"), c.get("line"))
        cat = c.get("category") or c.get("route") or "sink"
        cid = c.get("id") or "sa"
        add("source-lead", f"{cid} {cat} @ {loc}" if loc else f"{cid} {cat}", "source-audit:candidate")
        note_file(c.get("file"))
    # security-relevant structural facts are leads too (an authz absence / route is closed, not skipped).
    _SEC_STRUCT = {"route", "state-change-route", "auth-guard", "unauth-route", "id-from-param",
                   "missing-ownership-check", "mass-assignment", "writable-path", "web-exec-path"}

    def _structural_kind(k):
        """Pick the surface kind for a structural fact. When the app model is THIN for a type, a matching
        fact becomes that TYPED surface (so the code-audit slice carries entry-point/authz-route/state-op
        coverage without an app_model); otherwise it is a generic source-lead (unchanged behavior)."""
        if not have_state and k == "state-change-route":
            return "state-op"
        if not have_entry and k in ("route", "unauth-route", "web-exec-path"):
            return "entry-point"
        if not have_authz and k in ("auth-guard", "missing-ownership-check"):
            return "authz-route"
        return "source-lead"

    for sfact in sc.get("structural", []) or []:
        if not isinstance(sfact, dict):
            continue
        k = sfact.get("kind")
        loc = _loc(sfact.get("file"), sfact.get("line"))
        sid = sfact.get("id") or "sf"
        skind = _structural_kind(k)
        add(skind, f"{sid} {k} @ {loc}" if loc else f"{sid} {k}", "source-audit:structural")
        if skind != "source-lead" or k in _SEC_STRUCT:
            note_file(sfact.get("file"))
    for cc in sc.get("chain_candidates", []) or []:
        if not isinstance(cc, dict):
            continue
        ccid = cc.get("id") or "scc"
        title = cc.get("title") or cc.get("pattern") or "chain"
        add("source-lead", f"{ccid} {title}", "source-audit:chain")

    for f in sorted(hr_files):
        add("high-risk-file", f, "code-audit:model")

    return items


def mark(eng: Path, sid: str, status: str, by: str, reason: str):
    p = eng / LEDGER_NAME
    # Lock the read-modify-write so concurrent --mark calls (one per wave subagent) can't clobber each
    # other: the load happens INSIDE the lock, after any prior writer has committed.
    with _FileLock(p):
        led = _read_json(p)
        if not led:
            sys.exit(f"[!] no {LEDGER_NAME} in {eng} (run --plan first)")
        hit = None
        for s in led["surfaces"]:
            if s["id"] == sid or s.get("value") == sid:
                hit = s
                break
        if not hit:
            sys.exit(f"[!] surface not found: {sid}")
        hit["status"] = status
        if by:
            hit.setdefault("consumed_by", [])
            if by not in hit["consumed_by"]:
                hit["consumed_by"].append(by)
        if reason:
            hit["reason"] = reason
        led["generated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        atomic_write(p, json.dumps(led, indent=2))
    print(f"marked {sid} -> {status}")
    return 0


def update_ledger(eng: Path, mutate):
    """Merge-safe read-modify-write of surface_ledger.json — the concurrent WAVE-MERGE path.

    Acquires the per-file lock, reads the CURRENT on-disk ledger (so a parallel writer's just-committed
    mark is seen, never clobbered), applies ``mutate(led)`` (edit the dict in place or return a
    replacement), refreshes ``generated_at``, then ``atomic_write``s. Returns the written ledger, or None
    when no ledger exists / it is unreadable. Public + ADDITIVE: the existing writers (``mark`` and the
    ``--plan`` merge) keep their signatures and are already lock-safe; the engine-core wave-merge folds a
    wave's newly-discovered surface in race-free with ``update_ledger(eng, lambda led: merge_plan(led, items))``."""
    p = Path(eng) / LEDGER_NAME
    with _FileLock(p):
        led = _read_json(p)
        if not led:
            return None
        out = mutate(led)
        if out is None:
            out = led
        out.pop("_last_merge_added", None)   # merge_plan's transient counter never persists to disk
        out["generated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        atomic_write(p, json.dumps(out, indent=2))
        return out


def selftest() -> None:
    # routing
    assert "sqli" in route_surface("param") and route_surface("param")
    assert route_surface("identity") == ["authz", "api"]
    assert route_surface("unknown-kind") == []

    # partition: an out-of-enum kind (e.g. the inbox `content` surface) is REJECTED, not folded as n/a.
    good, bad = partition_items([
        {"kind": "param", "value": "q"},
        {"kind": "content", "value": "/sitemap.xml"},        # not a surface-ledger kind -> rejected
        {"kind": "param", "value": ""},                      # empty value -> rejected
    ])
    assert [g["value"] for g in good] == ["q"], good
    assert {b.get("kind") for b in bad} == {"content", "param"}, bad
    assert all(b.get("_reject_reason") for b in bad)

    # plan: routed element -> discovered; de-dupe; an invalid kind is dropped (not added as n/a)
    led = plan_from_items("demo", [
        {"kind": "param", "value": "q", "discovered_by": "content-discovery"},
        {"kind": "param", "value": "q"},                     # dup -> dropped
        {"kind": "identity", "value": "userA"},
        {"kind": "misc", "value": "unroutable"},             # invalid kind -> REJECTED
    ], warn=False)
    ids = {s["id"] for s in led["surfaces"]}
    assert len(ids) == 2, led
    byval = {s["value"]: s for s in led["surfaces"]}
    assert byval["q"]["status"] == "discovered" and byval["q"]["routed_to"]
    assert "unroutable" not in byval, "an invalid kind must not enter the ledger"

    # the VALID_KINDS constant must track the schema enum (drift guard)
    try:
        import json as _json
        _sp = Path(__file__).resolve().parent.parent / "skills" / "_contract" / "surface_ledger.schema.json"
        _enum = set(_json.loads(_sp.read_text(encoding="utf-8"))["$defs"]["surface"]["properties"]["kind"]["enum"])
        assert set(VALID_KINDS) == _enum, (set(VALID_KINDS) ^ _enum)
    except FileNotFoundError:  # pragma: no cover - schema always present in-repo
        pass

    # validate: a discovered routed surface is a gap
    ok, _l, msgs = validate(led)
    assert not ok and any("untested surface" in m for m in msgs)

    # mark every discovered element tested -> clean (n/a is fine)
    for s in led["surfaces"]:
        if s["status"] == "discovered":
            s["status"] = "tested"
    ok, _l, _m = validate(led)
    assert ok, _m

    # skipped without reason -> gap; with reason -> clean
    byval["q"]["status"] = "skipped"; byval["q"]["reason"] = ""
    assert not validate(led)[0]
    byval["q"]["reason"] = "login form param, auth class owns it"
    assert validate(led)[0]

    # surface_gaps mirrors validate's untested finding for the recall audit
    led2 = plan_from_items("demo", [{"kind": "param", "value": "id"}])
    g = surface_gaps(led2)
    assert g and g[0]["type"] == "untested-surface" and g[0]["severity"] == "high"

    # param->endpoint attribution: the SAME name on two endpoints is two DISTINCT surface elements.
    _p1, _n1 = _path_and_params("/_next/image?url=x&w=64")
    assert _p1 == "/_next/image" and _n1 == ["url", "w"], (_p1, _n1)
    assert _attr_param("url", "/_next/image") == "url@/_next/image"
    assert _attr_param("url", "https://h/a?x=1") == "url@/a"
    led_attr = plan_from_items("demo", [{"kind": "param", "value": "url@/_next/image"},
                                        {"kind": "param", "value": "url@/other"}])
    assert len({s["id"] for s in led_attr["surfaces"]}) == 2, "attributed params must not collapse"

    # content-kind discoveries route BACK to content-discovery (fix #5), never into the ledger.
    assert followup_route("content") == "content-discovery" and followup_route("param") is None
    rr = content_reroutes([{"kind": "content", "value": "/sitemap.xml", "discovered_by": "hunt"},
                           {"kind": "param", "value": "q"}])
    assert len(rr) == 1 and rr[0]["route_to"] == "content-discovery" and rr[0]["value"] == "/sitemap.xml"
    assert "content" not in VALID_KINDS, "content stays out of the testable surface-kind enum"

    # empty ledger: lenient normally, a gap under --strict
    assert validate({"surfaces": []})[0] is True
    assert validate({"surfaces": []}, strict=True)[0] is False

    # merge_plan (idempotent universal emission): preserves progress, adds only new elements.
    base = plan_from_items("demo", [{"kind": "param", "value": "q"}, {"kind": "param", "value": "id"}])
    base["surfaces"][0]["status"] = "tested"            # q was tested
    base["surfaces"][0].setdefault("consumed_by", []).append("sqli")
    merged = merge_plan(base, [{"kind": "param", "value": "q"},           # already present -> untouched
                               {"kind": "param", "value": "id"},          # already present -> untouched
                               {"kind": "identity", "value": "userB"}])   # NEW -> appended as discovered
    assert merged["_last_merge_added"] == 1, merged.get("_last_merge_added")
    bv = {s["value"]: s for s in merged["surfaces"]}
    assert bv["q"]["status"] == "tested" and "sqli" in bv["q"]["consumed_by"], "progress must survive re-plan"
    assert bv["userB"]["status"] == "discovered" and bv["userB"]["routed_to"]
    assert len(merged["surfaces"]) == 3
    # re-merging the SAME items adds nothing (idempotent).
    again = merge_plan(merged, [{"kind": "param", "value": "q"}])
    assert again["_last_merge_added"] == 0

    # --- white-box / source surface (code-audit) ---
    # the three source kinds route to the code-audit consumer (and are in the schema enum via the drift guard)
    assert route_surface("entry-point") == ["code-audit"]
    assert route_surface("source-lead") == ["code-audit"]
    assert route_surface("high-risk-file") == ["code-audit"]
    assert {"entry-point", "source-lead", "high-risk-file"}.issubset(VALID_KINDS)
    # the two first-class enumerated white-box surfaces grep can't see (state-op / authz-route) route to
    # the same code-audit consumer and are in the kind enum (drift-guarded against the schema above).
    assert route_surface("state-op") == ["code-audit"]
    assert route_surface("authz-route") == ["code-audit"]
    assert {"state-op", "authz-route"}.issubset(VALID_KINDS)
    _invp = plan_from_items("demo", [{"kind": "state-op", "value": "redeem [inv: single-use] @ c.py:9"},
                                     {"kind": "authz-route", "value": "POST /admin/import [priv: admin] @ a.py:4"}])
    assert all(s["routed_to"] == ["code-audit"] for s in _invp["surfaces"]) and len(_invp["surfaces"]) == 2
    assert not validate(_invp, routed_to="code-audit")[0]  # fresh -> an untested code-audit gap until closed

    # a mixed ledger: an untested black-box param AND an untested source-lead. Scoping validate to
    # code-audit gates ONLY its slice (the param gap is a sibling's problem, not code-audit's).
    mixed = plan_from_items("demo", [{"kind": "param", "value": "q"},
                                     {"kind": "entry-point", "value": "handler @ app.py:10"},
                                     {"kind": "source-lead", "value": "sa-001 sqli @ db.py:20"}])
    ca_only = _routed_subset(mixed["surfaces"], "code-audit")
    assert {s["kind"] for s in ca_only} == {"entry-point", "source-lead"}, ca_only
    # whole-ledger validate fails (param untested); code-audit-scoped validate fails on ITS own gaps only
    assert not validate(mixed)[0]
    ok_ca, _l, msgs_ca = validate(mixed, routed_to="code-audit")
    assert not ok_ca and all("param:" not in m for m in msgs_ca), msgs_ca
    # close the code-audit slice -> its scoped validate passes even while the param stays discovered
    for s in mixed["surfaces"]:
        if "code-audit" in (s.get("routed_to") or []):
            s["status"] = "tested"
    assert validate(mixed, routed_to="code-audit")[0]
    assert not validate(mixed)[0]  # the untested param still fails the whole-ledger gate

    # coverage_stats: honest figures + partial-coverage visibility (pct<100 while a gap is open)
    cov = coverage_stats(mixed, routed_to="code-audit")
    assert cov["total"] == 2 and cov["closed"] == 2 and cov["open_gaps"] == 0 and cov["pct"] == 100, cov
    part = plan_from_items("demo", [{"kind": "source-lead", "value": "sa-001 x @ a.py:1"},
                                    {"kind": "source-lead", "value": "sa-002 y @ b.py:2"}])
    part["surfaces"][0]["status"] = "tested"
    cp = coverage_stats(part, routed_to="code-audit")
    assert cp["pct"] == 50 and cp["open_gaps"] == 1, cp

    print("surface selftest: OK")


def main() -> int:
    ap = argparse.ArgumentParser(description="Redstrike surface-coverage ledger.")
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--mark")
    ap.add_argument("--status", choices=sorted(_MARK_STATUSES))
    ap.add_argument("--by", default="")
    ap.add_argument("--reason", default="")
    ap.add_argument("--engagement")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--routed-to", dest="routed_to", default=None,
                    help="--validate: gate only elements routed to this consumer (e.g. code-audit)")
    ap.add_argument("--fresh", action="store_true",
                    help="--plan: rebuild from scratch instead of the default idempotent merge")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return 0

    if args.plan:
        if not args.engagement:
            ap.error("--plan needs --engagement")
        eng = Path(args.engagement)
        # recon (black-box) surface + white-box source surface (entry points / source-audit leads /
        # high-risk files). Both best-effort: a pure black-box engagement has no source artifacts and a
        # pure white-box one has no recon feeders, so one of them is simply empty.
        items = load_recon_surfaces(eng) + load_source_surfaces(eng)
        p = eng / LEDGER_NAME
        # Lock the whole read-merge-write: the merge re-reads the on-disk ledger, so a concurrent wave
        # subagent's --mark (or another --plan) must not land between this read and its write.
        with _FileLock(p):
            if p.is_file() and not args.fresh:
                # Idempotent re-plan: emit universally + safely re-run as late feeders add surface,
                # preserving any tested/skipped progress. --fresh forces a clean rebuild.
                led = merge_plan(json.loads(p.read_text(encoding="utf-8")), items)
                added = led.pop("_last_merge_added", 0)
                atomic_write(p, json.dumps(led, indent=2))
                print(f"merged {eng / LEDGER_NAME}: +{added} new element(s), "
                      f"{len(led['surfaces'])} total (progress preserved)")
            else:
                led = plan_from_items(eng.name, items)
                atomic_write(p, json.dumps(led, indent=2))
                print(f"wrote {eng / LEDGER_NAME}: {len(led['surfaces'])} surface element(s)")
        return 0

    if args.mark:
        if not (args.engagement and args.status):
            ap.error("--mark needs --engagement and --status")
        return mark(Path(args.engagement), args.mark, args.status, args.by, args.reason)

    if args.validate:
        if not args.engagement:
            ap.error("--validate needs --engagement")
        p = Path(args.engagement) / LEDGER_NAME
        if not p.is_file():
            if args.as_json:
                print(json.dumps({"pass": (not args.strict), "messages": [f"no {LEDGER_NAME}"]}))
            else:
                print(f"no {LEDGER_NAME} — surface coverage not tracked"
                      + (" (FAIL under --strict)" if args.strict else " (warning)"))
            return 2 if args.strict else 0
        led = json.loads(p.read_text(encoding="utf-8"))
        ok, lines, msgs = validate(led, args.strict, routed_to=args.routed_to)
        cov = coverage_stats(led, routed_to=args.routed_to)
        if args.as_json:
            print(json.dumps({"pass": ok, "summary": lines, "messages": msgs, "coverage": cov}, indent=2))
        else:
            print(f"# Surface validation -- {args.engagement}"
                  + (f" (routed to {args.routed_to})" if args.routed_to else ""))
            for l in lines:
                print(f"  {l}")
            print(f"  coverage: {cov['pct']}% closed ({cov['closed']}/{cov['total']}), "
                  f"{cov['open_gaps']} untested gap(s)")
            for m in msgs:
                print(f"  - {m}")
            print(f"\n{'PASS' if ok else 'FAIL'}: surface ledger "
                  + ("fully tested/accounted." if ok else "has untested surface (see above)."))
        return 0 if ok else 2

    ap.error("choose one of --plan / --validate / --mark / --selftest")


if __name__ == "__main__":
    sys.exit(main())
