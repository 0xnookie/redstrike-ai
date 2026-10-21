#!/usr/bin/env python3
"""
coverage.py -- Redstrike DETERMINISTIC routing + coverage ledger (Phase 1).

Two jobs, one source of truth (skills/_contract/routing-map.json):

  --plan      Turn (routing map + recon signals + active phases) into a coverage ledger:
              every vulnerability category is marked `pending` (routed -> must be attempted),
              `skipped` (no trigger matched -> WITH a reason), or `n/a` (phase not in scope).
              This replaces model-interpreted routing. Writes coverage_ledger.json.

  --validate  Check an engagement's coverage_ledger.json: it accounts for EVERY category in the
              map (no silent omissions), nothing is still `pending` at close (an un-run route is a
              gap), every skipped/n-a/blocked has a reason, and (soft) categories with findings are
              `attempted`. Exit non-zero on a gap so the orchestrator cannot quietly skip a class.

The point of Phase 1: make "not attempted" a first-class, visible state. A category that never ran
and a category that ran-and-found-nothing must look different.

Stdlib only. Examples:
  python scripts/coverage.py --plan --signals signals.json --phases web \\
      --engagement engagements/acme-2026-10
  echo '["param:injectable","flow:auth","endpoint:https"]' | python scripts/coverage.py --plan --signals -
  python scripts/coverage.py --validate --engagement engagements/acme-2026-10
  python scripts/coverage.py --list
  python scripts/coverage.py --selftest
"""
import argparse
import datetime
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAP_PATH = ROOT / "skills" / "_contract" / "routing-map.json"
LEDGER_NAME = "coverage_ledger.json"
_OPEN_STATUSES = {"pending"}
_NEED_REASON = {"skipped", "n/a", "blocked"}


def load_map(path: Path = MAP_PATH) -> dict:
    if not path.is_file():
        sys.exit(f"[!] routing map not found: {path}")
    try:
        m = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        sys.exit(f"[!] routing map invalid JSON: {e}")
    if "categories" not in m:
        sys.exit("[!] routing map has no 'categories'")
    return m


def _load_signals(ref: str) -> set:
    """Signals come as a JSON list of strings, or an object {signal: truthy}. '-' = stdin."""
    if ref is None:
        return None
    raw = sys.stdin.read() if ref == "-" else Path(ref).read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        sys.exit(f"[!] signals not valid JSON: {e}")
    if isinstance(data, dict):
        return {k for k, v in data.items() if v}
    if isinstance(data, list):
        return {str(x) for x in data}
    sys.exit("[!] signals must be a JSON list or object")


def _active_phases(m: dict, requested: set, signals: set) -> set:
    """web + capability always; a phase activates when requested or when one of its auto_on signals fires;
    plus the phase of any category whose own trigger matched (so a stray signal pulls in its phase)."""
    phases = set(requested or set())
    for name, meta in m.get("phases", {}).items():
        if meta.get("default"):
            phases.add(name)
        auto = meta.get("auto_on")
        if auto and signals:
            if any(tok in signals for tok in auto.split("|")):
                phases.add(name)
    if signals:
        for c in m["categories"]:
            if any(t in signals for t in c.get("triggers", [])):
                phases.add(c["phase"])
    return phases


def plan(m: dict, signals: set, requested_phases: set, engagement: str = "") -> dict:
    """Deterministically route every category. signals=None means 'no recon signal data' -> attempt
    every in-scope category (recall-safe default); an empty set means 'signals gathered, none present'."""
    active = _active_phases(m, requested_phases, signals)
    cats = []
    for c in m["categories"]:
        phase = c["phase"]
        skills = ([c["feeder"]] if c.get("feeder") and c["feeder"] != "-" else []) + list(c.get("agents", []))
        entry = {"id": c["id"], "name": c.get("name", c["id"]), "phase": phase,
                 "skills": skills, "triggers_matched": [], "findings_count": 0,
                 "decided_by": "deterministic-map"}
        if phase == "capability":
            entry["status"] = "pipeline"
            entry["reason"] = "runs as a pipeline stage over accepted findings, not signal-routed"
        elif phase not in active:
            entry["status"] = "n/a"
            entry["reason"] = f"phase '{phase}' not in engagement scope (active: {', '.join(sorted(active))})"
        elif c.get("baseline"):
            entry["status"] = "pending"
            entry["reason"] = "baseline — always run for an in-scope target"
        else:
            matched = [t for t in c.get("triggers", []) if signals and t in signals]
            if matched:
                entry["status"] = "pending"
                entry["reason"] = "trigger matched: " + ", ".join(matched)
                entry["triggers_matched"] = matched
            elif signals is None:
                entry["status"] = "pending"
                entry["reason"] = "signals unavailable — attempted for coverage (recall-safe default)"
            else:
                entry["status"] = "skipped"
                entry["reason"] = c.get("skip_reason") or "no routing trigger matched"
        if c.get("risk"):
            entry["reason"] += f" [{c['risk']}-risk]"
        cats.append(entry)
    return {
        "engagement": engagement,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "map_version": m.get("version", 0),
        "active_phases": sorted(active),
        "signals_used": sorted(signals) if signals else [],
        "categories": cats,
    }


def validate(eng: Path, m: dict, strict: bool = False):
    """Return (ok, lines, warnings). ok=False => a real coverage gap (silent omission or pending-at-close)."""
    lines, warnings, errors = [], [], []
    ledger_path = eng / LEDGER_NAME
    if not ledger_path.is_file():
        return (not strict), [], [f"no {LEDGER_NAME} — category coverage not tracked "
                                  f"(run: scripts/coverage.py --plan --engagement {eng})"]
    try:
        led = json.loads(ledger_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return False, [], [f"{LEDGER_NAME} invalid JSON: {e}"]

    by_id = {c["id"]: c for c in led.get("categories", [])}
    map_ids = {c["id"] for c in m["categories"]}
    active = set(led.get("active_phases", []))

    # 1. every category in the map must appear in the ledger (no silent omission)
    missing = sorted(map_ids - set(by_id))
    for mid in missing:
        errors.append(f"category '{mid}' is in the routing map but ABSENT from the ledger (silent gap)")

    # 2. per-entry checks
    for cid, c in by_id.items():
        if cid not in map_ids:
            warnings.append(f"ledger category '{cid}' is not in the routing map (stale?)")
        st = c.get("status")
        if st in _OPEN_STATUSES:
            errors.append(f"'{cid}' is still '{st}' at validation — a routed category that never ran is a gap")
        if st in _NEED_REASON and not (c.get("reason") or "").strip():
            errors.append(f"'{cid}' is '{st}' but has no reason")

    # 3. soft cross-check against findings.json
    fj = eng / "findings.json"
    if fj.is_file():
        try:
            findings = json.loads(fj.read_text(encoding="utf-8"))
            n = len([f for f in findings if isinstance(f, dict)])
            attempted = [c for c in by_id.values() if c.get("status") == "attempted"]
            if n and not attempted:
                warnings.append(f"findings.json has {n} finding(s) but no category is marked 'attempted' "
                                f"(ledger not updated after the run?)")
        except json.JSONDecodeError:
            warnings.append("findings.json present but not valid JSON (skipped cross-check)")

    # tally
    from collections import Counter
    tally = Counter(c.get("status") for c in by_id.values())
    lines.append(f"ledger: {len(by_id)}/{len(map_ids)} categories; "
                 + ", ".join(f"{k}={tally[k]}" for k in sorted(tally)))
    lines.append(f"active phases: {', '.join(sorted(active)) or '(none)'}")
    return (not errors), lines, (errors + warnings),


def _print_plan_human(led: dict):
    from collections import Counter
    tally = Counter(c["status"] for c in led["categories"])
    print(f"# Coverage plan -- {led.get('engagement') or '(unnamed)'}  "
          f"(map v{led['map_version']}, phases: {', '.join(led['active_phases'])})")
    order = {"pending": 0, "attempted": 1, "blocked": 2, "pipeline": 3, "skipped": 4, "n/a": 5}
    for c in sorted(led["categories"], key=lambda c: (order.get(c["status"], 9), c["phase"], c["id"])):
        print(f"- [{c['status']:^9}] {c['id']:<22} ({c['phase']}) -- {c['reason']}")
    print("\n" + ", ".join(f"{k}={tally[k]}" for k in sorted(tally)))
    print(f"{tally['pending']} categories to run; {tally['skipped']} skipped with reason; {tally['n/a']} out-of-phase.")


def cmd_list(m: dict, as_json: bool):
    if as_json:
        print(json.dumps(m, indent=2))
        return
    print(f"# Routing map v{m.get('version')} -- {len(m['categories'])} categories")
    for c in m["categories"]:
        base = "baseline" if c.get("baseline") else ("|".join(c.get("triggers", [])) or "(pipeline)")
        print(f"- {c['id']:<22} [{c['phase']}] <- {base}")


def selftest() -> int:
    m = load_map()
    ids = [c["id"] for c in m["categories"]]
    assert len(ids) == len(set(ids)), "duplicate category ids"
    # every agent referenced exactly once; feeders/triggers well-formed
    agents = [a for c in m["categories"] for a in c.get("agents", [])]
    assert len(agents) == len(set(agents)), "an executor is mapped to two categories"
    sig_vocab = set(m.get("signals", {}))
    for c in m["categories"]:
        for t in c.get("triggers", []):
            assert t in sig_vocab, f"{c['id']} uses undefined signal '{t}'"
        if not c.get("baseline") and c["phase"] not in ("capability",):
            assert c.get("skip_reason"), f"{c['id']} non-baseline with no skip_reason"
    # plan with no signals -> every in-scope (web/capability + auto) category pending/pipeline, none skipped
    led = plan(m, None, {"web"})
    webcats = [c for c in led["categories"] if c["phase"] == "web"]
    assert all(c["status"] == "pending" for c in webcats), "no-signals plan should attempt all web cats"
    # plan with a signal set -> untriggered non-baseline web cats are skipped WITH reason
    led2 = plan(m, {"flow:auth", "endpoint:https"}, {"web"})
    sqli = next(c for c in led2["categories"] if c["id"] == "sqli")
    assert sqli["status"] == "skipped" and sqli["reason"], "sqli should skip-with-reason when not triggered"
    auth = next(c for c in led2["categories"] if c["id"] == "auth")
    assert auth["status"] == "pending", "auth should route on flow:auth"
    tls = next(c for c in led2["categories"] if c["id"] == "tls-attacks")
    assert tls["status"] == "pending", "tls-attacks should route on endpoint:https"
    # the 9 formerly-orphaned executors are all routable
    orphans = {"nosql-injection", "ldap-injection", "prototype-pollution", "race-condition",
               "parameter-pollution", "crypto-attacks", "tls-attacks", "supply-chain"}
    mapped = set(agents)
    assert orphans <= mapped, f"orphan executors missing: {orphans - mapped}"
    # web3/llm phases auto-activate on their signal
    led3 = plan(m, {"asset:smart-contract"}, {"web"})
    assert "web3" in led3["active_phases"], "web3 phase should auto-activate"
    sc = next(c for c in led3["categories"] if c["id"] == "sc")
    assert sc["status"] == "pending", "sc should route when contracts in scope"
    print("coverage.py selftest: OK "
          f"({len(ids)} categories, {len(set(agents))} executors, orphans wired, phases auto-activate)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Redstrike deterministic routing + coverage ledger.")
    ap.add_argument("--plan", action="store_true", help="emit a coverage ledger from map + signals")
    ap.add_argument("--validate", action="store_true", help="validate an engagement's coverage_ledger.json")
    ap.add_argument("--list", action="store_true", help="print the routing map categories")
    ap.add_argument("--selftest", action="store_true", help="internal consistency check (CI)")
    ap.add_argument("--signals", help="signals JSON file, or '-' for stdin (omit = none => attempt all)")
    ap.add_argument("--phases", default="web", help="comma-separated active phases (default: web)")
    ap.add_argument("--engagement", help="engagement dir (plan writes the ledger here; validate reads it)")
    ap.add_argument("--strict", action="store_true", help="validate: a missing ledger is a FAIL, not a warning")
    ap.add_argument("--json", action="store_true", dest="as_json", help="machine-readable output")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    m = load_map()
    if args.list:
        cmd_list(m, args.as_json)
        return 0

    if args.plan:
        signals = _load_signals(args.signals) if args.signals else None
        phases = {p.strip() for p in args.phases.split(",") if p.strip()}
        eng_name = Path(args.engagement).name if args.engagement else ""
        led = plan(m, signals, phases, eng_name)
        if args.engagement:
            out = Path(args.engagement)
            out.mkdir(parents=True, exist_ok=True)
            (out / LEDGER_NAME).write_text(json.dumps(led, indent=2) + "\n", encoding="utf-8")
            if args.as_json:
                print(json.dumps(led, indent=2))
            else:
                _print_plan_human(led)
                print(f"\nwrote {out / LEDGER_NAME}")
        else:
            print(json.dumps(led, indent=2) if args.as_json else None)
            if not args.as_json:
                _print_plan_human(led)
        return 0

    if args.validate:
        if not args.engagement:
            ap.error("--validate needs --engagement")
        ok, lines, msgs, = validate(Path(args.engagement), m, args.strict)
        if args.as_json:
            print(json.dumps({"engagement": args.engagement, "pass": ok,
                              "messages": msgs, "summary": lines}, indent=2))
        else:
            print(f"# Coverage validation -- {args.engagement}")
            for l in lines:
                print(f"  {l}")
            for msg in msgs:
                print(f"  - {msg}")
            print(f"\n{'PASS' if ok else 'FAIL'}: coverage ledger "
                  + ("accounts for every category." if ok else "has gaps (see above)."))
        return 0 if ok else 2

    ap.error("choose one of --plan / --validate / --list / --selftest")


if __name__ == "__main__":
    sys.exit(main())
