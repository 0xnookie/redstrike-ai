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
import sys
from datetime import datetime, timezone
from pathlib import Path

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
}


def route_surface(kind: str) -> list:
    """Category ids a surface of this kind should be tested by (deterministic)."""
    return list(KIND_ROUTES.get(kind, []))


def _sid(kind: str, value: str) -> str:
    return f"{kind}:" + hashlib.sha1(f"{kind}|{value}".encode()).hexdigest()[:10]


def plan_from_items(engagement: str, items) -> dict:
    """Build a fresh ledger from normalized discovered items [{kind,value,discovered_by?}, ...].
    Every element starts `discovered` (routes computed) or `n/a` when it routes to no category."""
    seen, surfaces = set(), []
    for it in items:
        kind = it.get("kind")
        value = str(it.get("value", "")).strip()
        if not kind or not value:
            continue
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


def validate(led: dict, strict: bool = False):
    """Return (ok, lines, msgs). ok=False => a surface gap (discovered-but-untested, or skipped w/o reason)."""
    errors, lines = [], []
    surfaces = led.get("surfaces", [])
    if not isinstance(surfaces, list):
        return False, [], ["surfaces is not a list"]
    from collections import Counter
    tally = Counter(s.get("status") for s in surfaces)
    for s in surfaces:
        st = s.get("status")
        if st == _OPEN_STATUS and s.get("routed_to"):
            errors.append(f"surface {s.get('kind')}:{s.get('value')!r} discovered but NEVER tested "
                          f"(routes to {', '.join(s.get('routed_to', []))}) — untested surface")
        if st in _NEED_REASON and not (s.get("reason") or "").strip():
            errors.append(f"surface {s.get('kind')}:{s.get('value')!r} is '{st}' without a reason")
    lines.append("surfaces: " + ", ".join(f"{k}={tally[k]}" for k in sorted(tally)) if tally
                 else "surfaces: (none enumerated)")
    # empty-but-present ledger isn't automatically a pass under --strict (recon enumerated nothing?)
    if strict and not surfaces:
        errors.append("surface ledger is empty — recon enumerated no surface (did the feeders run?)")
    return (not errors), lines, errors


def surface_gaps(led: dict) -> list:
    """Ranked recall gaps for the recall-audit altitude: each discovered-but-untested routed surface."""
    gaps = []
    for s in led.get("surfaces", []):
        if s.get("status") == _OPEN_STATUS and s.get("routed_to"):
            gaps.append({"category": (s.get("routed_to") or [None])[0], "type": "untested-surface",
                         "severity": "high",
                         "detail": f"{s.get('kind')} {s.get('value')!r} discovered by "
                                   f"{s.get('discovered_by','recon')} but fed to no executor",
                         "suggested_action": "route it to " + ", ".join(s.get("routed_to", [])) + " and test it"})
    return gaps


# ------------------------------- best-effort recon readers ------------------------------- #
def _read_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def load_recon_surfaces(eng: Path) -> list:
    """Enumerate surface items from the usual feeder artifacts (best-effort; missing = skipped)."""
    items = []
    hd = _read_json(eng / "host-discovery" / "host_discovery.json") or {}
    for h in hd.get("live_hosts", []) or []:
        if isinstance(h, dict) and h.get("url"):
            items.append({"kind": "endpoint", "value": h["url"], "discovered_by": "host-discovery"})
    for ep in hd.get("api_endpoints", []) or []:
        v = ep.get("path") if isinstance(ep, dict) else ep
        if v:
            items.append({"kind": "api-operation", "value": str(v), "discovered_by": "host-discovery"})
    az = _read_json(eng / "authz-context" / "authz_context.json") or {}
    for ident in az.get("identities", []) or []:
        lbl = ident.get("label") or ident.get("role") or ident.get("email") if isinstance(ident, dict) else ident
        if lbl:
            items.append({"kind": "identity", "value": str(lbl), "discovered_by": "authz-context"})
    # params from content-discovery (one per line in a params file)
    for pf in (eng / "content-discovery").glob("params*.txt") if (eng / "content-discovery").is_dir() else []:
        for line in pf.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                items.append({"kind": "param", "value": line, "discovered_by": "content-discovery"})
    # js-analysis endpoints/params (jsonl)
    ja = eng / "js-analysis"
    if ja.is_dir():
        for name, kind in (("endpoints.jsonl", "endpoint"), ("params.jsonl", "param")):
            p = ja / name
            if p.is_file():
                for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                    try:
                        o = json.loads(line)
                    except Exception:
                        continue
                    v = o.get("url") or o.get("path") or o.get("name") if isinstance(o, dict) else o
                    if v:
                        items.append({"kind": kind, "value": str(v), "discovered_by": "js-analysis"})
    return items


def mark(eng: Path, sid: str, status: str, by: str, reason: str):
    p = eng / LEDGER_NAME
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
    p.write_text(json.dumps(led, indent=2), encoding="utf-8")
    print(f"marked {sid} -> {status}")
    return 0


def selftest() -> None:
    # routing
    assert "sqli" in route_surface("param") and route_surface("param")
    assert route_surface("identity") == ["authz", "api"]
    assert route_surface("unknown-kind") == []

    # plan: routed element -> discovered; unroutable kind -> n/a; de-dupe
    led = plan_from_items("demo", [
        {"kind": "param", "value": "q", "discovered_by": "content-discovery"},
        {"kind": "param", "value": "q"},                     # dup -> dropped
        {"kind": "identity", "value": "userA"},
        {"kind": "misc", "value": "unroutable"},             # unknown kind -> n/a
    ])
    ids = {s["id"] for s in led["surfaces"]}
    assert len(ids) == 3, led
    byval = {s["value"]: s for s in led["surfaces"]}
    assert byval["q"]["status"] == "discovered" and byval["q"]["routed_to"]
    assert byval["unroutable"]["status"] == "n/a" and byval["unroutable"]["reason"]

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
        items = load_recon_surfaces(eng)
        p = eng / LEDGER_NAME
        if p.is_file() and not args.fresh:
            # Idempotent re-plan: emit universally + safely re-run as late feeders add surface,
            # preserving any tested/skipped progress. --fresh forces a clean rebuild.
            led = merge_plan(json.loads(p.read_text(encoding="utf-8")), items)
            added = led.pop("_last_merge_added", 0)
            p.write_text(json.dumps(led, indent=2), encoding="utf-8")
            print(f"merged {eng / LEDGER_NAME}: +{added} new element(s), "
                  f"{len(led['surfaces'])} total (progress preserved)")
        else:
            led = plan_from_items(eng.name, items)
            p.write_text(json.dumps(led, indent=2), encoding="utf-8")
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
        ok, lines, msgs = validate(led, args.strict)
        if args.as_json:
            print(json.dumps({"pass": ok, "summary": lines, "messages": msgs}, indent=2))
        else:
            print(f"# Surface validation -- {args.engagement}")
            for l in lines:
                print(f"  {l}")
            for m in msgs:
                print(f"  - {m}")
            print(f"\n{'PASS' if ok else 'FAIL'}: surface ledger "
                  + ("fully tested/accounted." if ok else "has untested surface (see above)."))
        return 0 if ok else 2

    ap.error("choose one of --plan / --validate / --mark / --selftest")


if __name__ == "__main__":
    sys.exit(main())
