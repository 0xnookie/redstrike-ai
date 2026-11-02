#!/usr/bin/env python3
"""
reconverge.py -- finding -> recon re-convergence controller (recall fix #6).

WHY THIS EXISTS (recall fix, 2026-11-02):
  The Redstrike pipeline is single-pass: recon -> plan (coverage + surface ledgers) -> hunt ->
  report. The coverage and surface ledgers are built ONCE, from the recon signals available
  right after recon. But hunting DISCOVERS new attack surface:
    - an SSRF reaches an internal host / cloud metadata (new `host:internal`, `asset:cloud`);
    - a finding leaks an API base-url, a vhost, a subdomain, new params;
    - an auth bypass yields a new identity (the second account IDOR/BOLA needed);
    - a config leak reveals endpoints recon never saw.
  Nothing feeds those back. The newly-found surface is never routed to the executors that
  should test it, so whole classes silently miss the enlarged surface -- and a run can reach
  `report` having never re-converged (the Oct-20 failure shape: terminate before closure).

THE RULE THIS ENCODES (a monotone work-list fixpoint):
  A finding that reveals new signal/surface RE-OPENS the classes that signal/surface now routes
  to (flip them from a terminal state back to `pending`), and the engagement is only DONE when a
  re-convergence pass adds nothing new -- the fixpoint. This is the symmetric recall control to
  the escalation ladder (depth within a class) and the surface ledger (breadth within recon):
  re-convergence is breadth DISCOVERED DURING the hunt.

TERMINATION (why the loop always ends): each pass processes only the DELTA -- signals/surface not
  already seen -- and `apply()` folds that delta into the ledgers (the seen-set grows monotonically
  and never shrinks). Signals are drawn from a finite vocabulary and discoverable surface is finite,
  so the delta empties after finitely many passes: `converged` becomes True. MAX_ROUNDS is a safety
  bound against a misbehaving emitter (like sqli_union's MAX_COLUMNS), not a feature limit.

SCOPE SAFETY: a new signal only RE-OPENS a class whose phase is already active (`attempted`/`skipped`).
  A new signal that matches an out-of-phase (`n/a`) class is surfaced as a `replan_candidate` for the
  operator (it may mean a whole new phase -- e.g. `asset:smart-contract` -> web3 -- which is a scope
  decision), never auto-activated. `blocked` classes are left for the operator too.

Pure logic for the decision core (`reconverge`); thin loaders/applier read & write the ledgers.
Stdlib only. `python scripts/reconverge.py --selftest`.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COVERAGE_LEDGER = "coverage_ledger.json"
SURFACE_LEDGER = "surface_ledger.json"
INBOX = "reconvergence/inbox.jsonl"  # executors append observation records here

# Terminal statuses that are safe to re-open automatically: the class ran (or was skipped) within an
# ACTIVE phase, so re-running it against newly-found surface is in scope. `n/a` (phase out of scope) and
# `blocked` (operator/RoE) are never auto-reopened -- they become operator-facing candidates instead.
TERMINAL_REOPENABLE = {"attempted", "skipped"}

# Safety bound on the re-convergence loop (termination is guaranteed by monotonicity; this only guards
# a buggy emitter that re-announces "new" surface forever). Not a feature ceiling.
MAX_ROUNDS = 64


def _default_router(kind: str):
    """Coarse kind -> category-id routes, reused from surface.py so the two ledgers agree."""
    try:
        import surface as _sf  # scripts/ on sys.path
    except ImportError:  # pragma: no cover - path fallback
        import importlib.util as _ilu
        _sp = _ilu.spec_from_file_location("surface", str(ROOT / "scripts" / "surface.py"))
        _sf = _ilu.module_from_spec(_sp)
        _sp.loader.exec_module(_sf)
    return _sf.route_surface(kind)


def _phase_auto_tokens(map_phases) -> dict:
    """phase_name -> set(auto_on signal tokens) from the routing map's phases block."""
    out = {}
    for name, meta in (map_phases or {}).items():
        auto = (meta or {}).get("auto_on")
        if auto:
            out[name] = set(auto.split("|"))
    return out


def reconverge(seen_signals, surface_keys, categories, observations, map_categories,
               map_phases=None, surface_router=None) -> dict:
    """Compute one re-convergence pass from already-parsed inputs (pure logic).

    seen_signals:  set[str]              -- signals already known (coverage ledger `signals_used`)
    surface_keys:  set[(kind, value)]    -- surface elements already in the surface ledger
    categories:    list[dict]            -- coverage ledger entries [{id,status,triggers?,...}]
    observations:  list[dict]            -- mid-hunt discoveries, each
                     {"source": "<skill>", "signals": [...], "surface": [{kind,value,discovered_by?}]}
    map_categories: routing-map categories [{id,triggers,phase,...}]
    map_phases:    routing-map `phases` block (for phase-level replan detection); optional
    surface_router: callable(kind)->[category ids]; defaults to surface.route_surface

    Returns a plan dict:
      {converged, added_signals, added_surface, added_surface_unrouted,
       reopen:[{id,from_status,triggered_by}], replan_candidates:[{id,triggered_by}],
       replan_phases:[...], summary:{...}}
    `converged` is True iff nothing actionable is new -> the fixpoint, safe to report.
    """
    router = surface_router or _default_router
    seen = set(seen_signals or ())
    skeys = {(k, v) for (k, v) in (surface_keys or ())}
    trig_by_cat = {c["id"]: set(c.get("triggers", []) or []) for c in map_categories}
    status_by_cat = {c.get("id"): c.get("status") for c in categories}

    # --- gather the observation delta ---
    obs_signals, obs_surface = set(), []
    for o in observations or []:
        for s in o.get("signals", []) or []:
            obs_signals.add(str(s))
        for item in o.get("surface", []) or []:
            k, v = item.get("kind"), str(item.get("value", "")).strip()
            if k and v:
                obs_surface.append({"kind": k, "value": v,
                                    "discovered_by": item.get("discovered_by", o.get("source", "hunt"))})

    added_signals = obs_signals - seen

    routed_new, unrouted_new, seen_new = [], [], set()
    for it in obs_surface:
        key = (it["kind"], it["value"])
        if key in skeys or key in seen_new:
            continue
        seen_new.add(key)
        routes = list(router(it["kind"]) or [])
        rec = {**it, "routed_to": routes}
        (routed_new if routes else unrouted_new).append(rec)

    # --- decide reopens (signal-driven + surface-driven), only on active-phase terminal classes ---
    reopen = {}  # id -> set(triggers)

    def _reopen(cid, tok):
        if status_by_cat.get(cid) in TERMINAL_REOPENABLE:
            reopen.setdefault(cid, set()).add(tok)
            return True
        return False

    for cid, trigs in trig_by_cat.items():
        for tok in sorted(trigs & added_signals):
            _reopen(cid, tok)

    ledger_ids = set(status_by_cat)
    for s in routed_new:
        tok = f"surface:{s['kind']}:{s['value']}"
        for rid in s["routed_to"]:
            if rid in ledger_ids:
                _reopen(rid, tok)

    # --- out-of-scope leads the operator must decide on (never auto-activated) ---
    replan_candidates = []
    for cid, trigs in trig_by_cat.items():
        if status_by_cat.get(cid) == "n/a":
            m = sorted(trigs & added_signals)
            if m:
                replan_candidates.append({"id": cid, "triggered_by": m})
    replan_phases = sorted(
        name for name, toks in _phase_auto_tokens(map_phases).items() if toks & added_signals
    )

    added_surface = routed_new
    converged = not added_signals and not added_surface and not unrouted_new

    plan = {
        "converged": converged,
        "added_signals": sorted(added_signals),
        "added_surface": added_surface,
        "added_surface_unrouted": unrouted_new,
        "reopen": [{"id": cid, "from_status": status_by_cat.get(cid),
                    "triggered_by": sorted(toks)} for cid, toks in sorted(reopen.items())],
        "replan_candidates": sorted(replan_candidates, key=lambda c: c["id"]),
        "replan_phases": replan_phases,
    }
    plan["summary"] = {
        "converged": converged,
        "added_signals": len(added_signals),
        "added_surface": len(added_surface),
        "reopened": len(reopen),
        "replan_candidates": len(replan_candidates),
    }
    return plan


def apply_plan(coverage_led: dict, surface_led: dict, plan: dict):
    """Fold a re-convergence plan back into the two ledgers (the monotone step).

    Re-opened categories flip to `pending` with provenance; `added_signals` join `signals_used`
    (so the SAME observation produces no delta next pass -> the fixpoint); new surface is appended
    as `discovered` (routes computed) so the surface gate tracks it. Returns (coverage_led, surface_led).
    """
    by_id = {c.get("id"): c for c in coverage_led.get("categories", [])}
    for r in plan.get("reopen", []):
        c = by_id.get(r["id"])
        if not c:
            continue
        c["status"] = "pending"
        c["reason"] = "reopened by re-convergence: " + ", ".join(r["triggered_by"])
        c["reopened_rounds"] = int(c.get("reopened_rounds", 0)) + 1
        prev = set(c.get("reopened_by", []) or [])
        c["reopened_by"] = sorted(prev | set(r["triggered_by"]))
        c["findings_count"] = 0  # a fresh pass against the new surface

    used = set(coverage_led.get("signals_used", []) or [])
    coverage_led["signals_used"] = sorted(used | set(plan.get("added_signals", [])))
    coverage_led["reconvergence_rounds"] = int(coverage_led.get("reconvergence_rounds", 0)) + 1

    new_items = [{"kind": s["kind"], "value": s["value"], "discovered_by": s.get("discovered_by", "hunt")}
                 for s in (plan.get("added_surface", []) + plan.get("added_surface_unrouted", []))]
    if new_items and surface_led is not None:
        try:
            import surface as _sf
        except ImportError:  # pragma: no cover
            import importlib.util as _ilu
            _sp = _ilu.spec_from_file_location("surface", str(ROOT / "scripts" / "surface.py"))
            _sf = _ilu.module_from_spec(_sp)
            _sp.loader.exec_module(_sf)
        fresh = _sf.plan_from_items(surface_led.get("engagement", ""), new_items)["surfaces"]
        have = {s["id"] for s in surface_led.get("surfaces", [])}
        surface_led.setdefault("surfaces", []).extend(s for s in fresh if s["id"] not in have)
        surface_led["generated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return coverage_led, surface_led


# ------------------------------- engagement I/O (thin, best-effort) ------------------------------- #
def _read_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _load_map():
    m = _read_json(ROOT / "skills" / "_contract" / "routing-map.json") or {}
    return m.get("categories", []), m.get("phases", {})


def load_observations(eng: Path) -> list:
    p = eng / INBOX
    obs = []
    if p.is_file():
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line:
                try:
                    obs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return obs


def load_and_plan(eng: Path) -> dict:
    cov = _read_json(eng / COVERAGE_LEDGER) or {}
    surf = _read_json(eng / SURFACE_LEDGER) or {}
    cats = cov.get("categories", [])
    seen = set(cov.get("signals_used", []) or [])
    skeys = {(s.get("kind"), s.get("value")) for s in surf.get("surfaces", [])}
    mapc, mapp = _load_map()
    return reconverge(seen, skeys, cats, load_observations(eng), mapc, mapp)


def reconverge_hard_errors(eng: Path) -> list:
    """HARD gate for verify_completion (fix #6): active only when a report AND a non-empty inbox exist.

    If the hunt recorded mid-hunt discoveries (the inbox) but a re-convergence pass still has unseen
    signals/surface, the engagement is reporting BEFORE it re-converged -- newly-found surface was never
    routed. Mirrors the coverage/surface hard gates. No inbox => no gate (re-convergence is opportunistic).
    """
    if not (eng / "report" / "findings_consolidated.json").is_file():
        return []
    if not load_observations(eng):
        return []
    plan = load_and_plan(eng)
    if plan["converged"]:
        return []
    s = plan["summary"]
    detail = (f"{s['added_signals']} new signal(s), {s['added_surface']} new surface element(s) "
              f"discovered during the hunt were never re-converged "
              f"({s['reopened']} class(es) to re-open)")
    return [f"re-convergence gate (report present -> must reach fixpoint): {detail} — "
            f"run scripts/reconverge.py --apply then re-run the reopened classes"]


def selftest() -> None:
    mapc = [
        {"id": "xss", "phase": "web", "triggers": ["sink:html-reflect", "sink:dom", "param:any"]},
        {"id": "sqli", "phase": "web", "triggers": ["param:injectable"]},
        {"id": "ssrf", "phase": "web", "triggers": ["param:url-fetching"]},
        {"id": "cloud", "phase": "cloud", "triggers": ["asset:cloud"]},
        {"id": "authz", "phase": "web", "triggers": ["identity:multi"]},
        {"id": "exposed-surface", "phase": "web", "triggers": []},
    ]
    mapp = {"cloud": {"auto_on": "asset:cloud"}, "web3": {"auto_on": "asset:smart-contract"}}

    # 1) An SSRF finding reveals an internal host + cloud metadata. ssrf already ran (attempted);
    #    a new `asset:cloud` signal must re-open ssrf, and surface the cloud phase for operator replan
    #    (cloud is phase-gated / out of the active web scope, so it is NOT auto-activated).
    cats = [{"id": "ssrf", "status": "attempted", "findings_count": 1, "triggers": ["param:url-fetching"]},
            {"id": "cloud", "status": "n/a", "reason": "cloud phase not in scope", "triggers": ["asset:cloud"]},
            {"id": "exposed-surface", "status": "attempted", "findings_count": 0}]
    obs = [{"source": "ssrf", "signals": ["asset:cloud", "param:url-fetching"],
            "surface": [{"kind": "endpoint", "value": "http://169.254.169.254/latest/meta-data/"}]}]
    p = reconverge(set(), set(), cats, obs, mapc, mapp)
    assert p["converged"] is False
    assert "asset:cloud" in p["added_signals"] and "param:url-fetching" in p["added_signals"]
    reopened = {r["id"] for r in p["reopen"]}
    # ssrf reopened by its own trigger; exposed-surface reopened by the new endpoint surface it routes to.
    assert "ssrf" in reopened, p["reopen"]
    assert "exposed-surface" in reopened, p["reopen"]
    # cloud is n/a (phase out of scope) -> NOT auto-reopened; it's a replan candidate + a replan phase.
    assert "cloud" not in reopened
    assert any(c["id"] == "cloud" for c in p["replan_candidates"])
    assert "cloud" in p["replan_phases"]

    # 2) A new identity (auth bypass) re-opens authz (the second account IDOR/BOLA needed).
    cats2 = [{"id": "authz", "status": "skipped", "reason": "only one identity", "triggers": ["identity:multi"]}]
    p2 = reconverge(set(), set(), cats2, [{"source": "auth-bypass", "signals": ["identity:multi"]}], mapc, mapp)
    assert {r["id"] for r in p2["reopen"]} == {"authz"}
    assert p2["reopen"][0]["from_status"] == "skipped"

    # 3) FIXPOINT: once the delta is already in the ledgers, the same observation adds nothing.
    seen = {"asset:cloud", "param:url-fetching"}
    skeys = {("endpoint", "http://169.254.169.254/latest/meta-data/")}
    p3 = reconverge(seen, skeys, cats, obs, mapc, mapp)
    assert p3["converged"] is True and not p3["reopen"], p3

    # 4) apply() folds the delta in so the NEXT pass converges (termination, end-to-end).
    cov = {"categories": [dict(c) for c in cats], "signals_used": []}
    surf = {"engagement": "demo", "surfaces": []}
    apply_plan(cov, surf, p)
    assert {c["id"] for c in cov["categories"] if c["status"] == "pending"} >= {"ssrf", "exposed-surface"}
    ss = next(c for c in cov["categories"] if c["id"] == "ssrf")
    assert ss["reopened_rounds"] == 1 and ss["findings_count"] == 0 and ss["reopened_by"]
    assert "asset:cloud" in cov["signals_used"]
    assert any(s["kind"] == "endpoint" for s in surf["surfaces"]), "new surface appended to the ledger"
    # re-run reconverge on the APPLIED ledgers with the same inbox -> converged.
    seen2 = set(cov["signals_used"])
    skeys2 = {(s["kind"], s["value"]) for s in surf["surfaces"]}
    cats_applied = [{"id": c["id"], "status": c["status"], "triggers": next(
        (mc["triggers"] for mc in mapc if mc["id"] == c["id"]), [])} for c in cov["categories"]]
    p4 = reconverge(seen2, skeys2, cats_applied, obs, mapc, mapp)
    assert p4["converged"] is True, p4

    # 5) Nothing discovered at all -> converged (the common clean case).
    assert reconverge({"param:injectable"}, set(), cats, [], mapc, mapp)["converged"] is True

    # 6) A pending class is NOT "reopened" (it's already going to run); only terminal classes are.
    cats6 = [{"id": "sqli", "status": "pending", "triggers": ["param:injectable"]}]
    p6 = reconverge(set(), set(), cats6, [{"signals": ["param:injectable"]}], mapc, mapp)
    assert p6["reopen"] == [] and p6["converged"] is False  # new signal still recorded (not converged yet)

    # 7) Unrouted new surface is recorded but creates no reopen, and still blocks convergence until applied.
    p7 = reconverge(set(), set(), cats, [{"surface": [{"kind": "weird", "value": "x"}]}], mapc, mapp)
    assert p7["added_surface_unrouted"] and not p7["reopen"] and p7["converged"] is False

    print("reconverge selftest: OK")


def main() -> int:
    ap = argparse.ArgumentParser(description="Redstrike finding->recon re-convergence controller.")
    ap.add_argument("--plan", action="store_true", help="compute a re-convergence pass from the inbox + ledgers")
    ap.add_argument("--apply", action="store_true", help="plan, then fold the delta back into the ledgers")
    ap.add_argument("--validate", action="store_true", help="exit non-zero if the inbox hasn't re-converged")
    ap.add_argument("--engagement", help="engagement dir")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return 0
    if not args.engagement:
        ap.error("choose --plan/--apply/--validate with --engagement, or --selftest")
    eng = Path(args.engagement)

    if args.plan or args.apply:
        plan = load_and_plan(eng)
        if args.apply and not plan["converged"]:
            cov = _read_json(eng / COVERAGE_LEDGER) or {}
            surf = _read_json(eng / SURFACE_LEDGER)
            apply_plan(cov, surf if surf is not None else {"engagement": eng.name, "surfaces": []}, plan)
            (eng / COVERAGE_LEDGER).write_text(json.dumps(cov, indent=2) + "\n", encoding="utf-8")
            if surf is not None:
                (eng / SURFACE_LEDGER).write_text(json.dumps(surf, indent=2) + "\n", encoding="utf-8")
        if args.as_json:
            print(json.dumps(plan, indent=2))
        else:
            s = plan["summary"]
            print(f"# Re-convergence -- {eng}")
            print(f"  converged: {plan['converged']}")
            print(f"  new signals: {s['added_signals']}  new surface: {s['added_surface']}  "
                  f"reopen: {s['reopened']}  replan-candidates: {s['replan_candidates']}")
            for r in plan["reopen"]:
                print(f"  - re-open {r['id']} (was {r['from_status']}) <- {', '.join(r['triggered_by'])}")
            for c in plan["replan_candidates"]:
                print(f"  - replan? {c['id']} (out-of-phase) <- {', '.join(c['triggered_by'])}")
            if plan["replan_phases"]:
                print(f"  - new phase signal(s): {', '.join(plan['replan_phases'])} (operator scope decision)")
            if args.apply:
                print("  (ledgers updated)" if not plan["converged"] else "  (already converged; nothing to apply)")
        return 0 if plan["converged"] else 2

    if args.validate:
        plan = load_and_plan(eng)
        errs = reconverge_hard_errors(eng)
        if args.as_json:
            print(json.dumps({"engagement": str(eng), "converged": plan["converged"],
                              "errors": errs, "summary": plan["summary"]}, indent=2))
        else:
            print(f"{'PASS' if plan['converged'] else 'OPEN'}: re-convergence "
                  + ("reached a fixpoint." if plan["converged"]
                     else f"has {plan['summary']['added_signals']} new signal(s) / "
                          f"{plan['summary']['added_surface']} new surface element(s) to route."))
            for e in errs:
                print(f"  - {e}")
        return 0 if plan["converged"] else 2

    ap.error("choose one of --plan / --apply / --validate / --selftest")


if __name__ == "__main__":
    sys.exit(main())
