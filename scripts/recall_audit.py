#!/usr/bin/env python3
"""
recall_audit.py -- the "what did we miss?" altitude (recall fix #4).

Redstrike has two review altitudes and they both face the SAME way — toward precision:
  - review.md  (mechanical): did each step run and emit well-formed output?
  - verify.md  (semantic, the ~60 `*-verify` agents): is each REPORTED finding real/in-scope/rated?
Both only ever look at findings that WERE produced. Nothing systematically asks the recall question:
**what SHOULD have been found but wasn't?** This module is the deterministic backbone of that third,
false-NEGATIVE altitude (adjudicated by the `recall-audit` reviewer agent).

It flags gaps NO existing gate catches:
  - shallow-clear      : a class ran, found nothing, BUT recon signalled the surface applies and the
                         escalation ladder (scripts/escalation.py) was not exhausted -> a likely miss.
  - skipped-but-signalled: a class was skipped/n-a although an available recon signal matches its
                         routing triggers -> a route wrongly dropped.
  - pending-at-close   : a routed class never ran (also caught by the coverage gate; repeated here so the
                         recall report is self-contained).

coverage.py proves categories are ACCOUNTED FOR; this asks whether an ACCOUNTED-FOR-as-clear result is
actually trustworthy. Pure logic (inputs injected) so it is unit-testable with no network; a thin
`load_and_audit(eng)` reads the engagement artifacts. Stdlib only. `python scripts/recall_audit.py --selftest`.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

try:
    import escalation as _esc  # when scripts/ is on sys.path
except ImportError:  # pragma: no cover - path fallback
    import importlib.util as _ilu
    _spec = _ilu.spec_from_file_location("escalation", str(Path(__file__).resolve().parent / "escalation.py"))
    _esc = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_esc)


def _triggers_by_cat(map_categories) -> dict:
    return {c["id"]: set(c.get("triggers", []) or []) for c in map_categories}


def audit(categories, signals, map_categories, escalations=None) -> dict:
    """Compute recall gaps from already-parsed inputs.

    categories:   ledger entries [{id,status,reason?,triggers_matched?,findings_count?}, ...]
    signals:      iterable of recon signal tokens actually available for this engagement
    map_categories: routing-map categories [{id,triggers,...}, ...]
    escalations:  {category_id: [escalation-technique-ids already tried]} (optional)

    Returns {gaps: [...], summary: {...}} with gaps ranked (high before medium).
    """
    sig = set(signals or ())
    esc_done = escalations or {}
    trig = _triggers_by_cat(map_categories)
    gaps = []

    for c in categories:
        cid = c.get("id")
        st = c.get("status")
        matched = set(c.get("triggers_matched") or [])
        # if the ledger didn't record which signals routed it, fall back to map-triggers ∩ available signals
        high_prior = bool(matched) or bool(trig.get(cid, set()) & sig)
        n = c.get("findings_count") or 0

        if st == "pending":
            gaps.append({"category": cid, "type": "pending-at-close", "severity": "high",
                         "detail": "routed category never ran",
                         "suggested_action": "run it, or record an explicit skip reason"})

        elif st == "attempted" and n == 0:
            prior = "high" if high_prior else "low"
            a = _esc.assess(cid, 0, prior, escalations_done=esc_done.get(cid, []))
            if a["verdict"] == "escalate":
                gaps.append({"category": cid, "type": "shallow-clear", "severity": "high",
                             "detail": ("empty on a recon-signalled surface with the escalation ladder "
                                        "unexhausted — a clear here is not yet trustworthy"),
                             "suggested_action": "escalate: " + ", ".join(a["remaining"][:4])})

        elif st in ("skipped", "n/a"):
            if trig.get(cid, set()) & sig:
                gaps.append({"category": cid, "type": "skipped-but-signalled", "severity": "high",
                             "detail": ("skipped although an available recon signal matches its triggers: "
                                        + ", ".join(sorted(trig[cid] & sig))),
                             "suggested_action": "un-skip and run the class"})
            elif st == "skipped" and len((c.get("reason") or "").strip()) < 12:
                gaps.append({"category": cid, "type": "weak-skip-reason", "severity": "medium",
                             "detail": "skipped with a missing/too-terse reason",
                             "suggested_action": "state a concrete, signal-based reason or run the class"})

    order = {"high": 0, "medium": 1, "low": 2}
    gaps.sort(key=lambda g: (order.get(g["severity"], 9), g["type"], g["category"] or ""))
    from collections import Counter
    by_type = Counter(g["type"] for g in gaps)
    return {"gaps": gaps, "summary": {"total": len(gaps),
                                      "high": sum(1 for g in gaps if g["severity"] == "high"),
                                      "by_type": dict(by_type)}}


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _load_signals(eng: Path) -> set:
    """Union recon signals from the usual feeder artifacts (best-effort; missing = empty)."""
    out = set()
    for p in list(eng.glob("*/signals.json")) + [eng / "signals.json"]:
        if p.is_file():
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            sigs = d.get("signals") if isinstance(d, dict) else d
            if isinstance(sigs, list):
                out |= {str(s) for s in sigs}
    return out


def load_and_audit(eng: Path) -> dict:
    """Read an engagement's ledger + signals + routing map and run audit()."""
    led_p = eng / "coverage_ledger.json"
    if not led_p.is_file():
        return {"gaps": [{"category": None, "type": "no-ledger", "severity": "high",
                          "detail": "no coverage_ledger.json — recall cannot be audited",
                          "suggested_action": "scripts/coverage.py --plan --engagement <dir>"}],
                "summary": {"total": 1, "high": 1, "by_type": {"no-ledger": 1}}}
    led = json.loads(led_p.read_text(encoding="utf-8"))
    mp = json.loads((_repo_root() / "skills" / "_contract" / "routing-map.json").read_text(encoding="utf-8"))
    escalations = {c["id"]: c.get("escalations", []) for c in led.get("categories", []) if c.get("escalations")}
    return audit(led.get("categories", []), _load_signals(eng), mp.get("categories", []), escalations)


def selftest() -> None:
    mapc = [
        {"id": "xss", "triggers": ["sink:html-reflect", "sink:dom", "param:any"]},
        {"id": "sqli", "triggers": ["param:injectable"]},
        {"id": "ssrf", "triggers": ["param:url-fetching"]},
        {"id": "secrets", "triggers": []},
    ]

    # 1) shallow-clear: sqli ran, 0 findings, but the ledger says an injectable param routed it,
    #    and the ladder wasn't exhausted -> a HIGH recall gap.
    led = [{"id": "sqli", "status": "attempted", "findings_count": 0,
            "triggers_matched": ["param:injectable"]}]
    r = audit(led, {"param:injectable"}, mapc)
    assert r["summary"]["total"] == 1 and r["gaps"][0]["type"] == "shallow-clear", r
    assert "derive-not-assume" in r["gaps"][0]["suggested_action"]

    # 2) escalation exhausted -> NOT a gap (honest clear-after-escalation).
    full = _esc.ladder_for("sqli")
    r = audit(led, {"param:injectable"}, mapc, escalations={"sqli": full})
    assert r["summary"]["total"] == 0, r

    # 3) low-prior empty (no matching signal) -> NOT a gap.
    led2 = [{"id": "ssrf", "status": "attempted", "findings_count": 0, "triggers_matched": []}]
    assert audit(led2, set(), mapc)["summary"]["total"] == 0

    # 4) skipped-but-signalled: xss skipped, but a DOM sink signal is present -> HIGH gap.
    led3 = [{"id": "xss", "status": "skipped", "reason": "no reflection seen", "findings_count": 0}]
    r = audit(led3, {"sink:dom"}, mapc)
    assert r["gaps"][0]["type"] == "skipped-but-signalled", r

    # 5) legitimately skipped (no matching signal) with a real reason -> NOT a gap.
    assert audit(led3, set(), mapc)["summary"]["total"] == 0

    # 6) weak skip reason (no signal, terse reason) -> MEDIUM gap.
    led4 = [{"id": "xss", "status": "skipped", "reason": "n/a", "findings_count": 0}]
    r = audit(led4, set(), mapc)
    assert r["gaps"][0]["type"] == "weak-skip-reason" and r["gaps"][0]["severity"] == "medium"

    # 7) pending at close -> HIGH gap; a found class -> no gap; ranking puts high first.
    led5 = [{"id": "sqli", "status": "pending"},
            {"id": "xss", "status": "attempted", "findings_count": 3, "triggers_matched": ["sink:dom"]},
            {"id": "secrets", "status": "skipped", "reason": "x"}]
    r = audit(led5, set(), mapc)
    types = {g["type"] for g in r["gaps"]}
    assert "pending-at-close" in types
    assert all(g["category"] != "xss" for g in r["gaps"]), "a class with findings is not a gap"
    assert r["gaps"][0]["severity"] == "high"

    print("recall_audit selftest: OK")


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        selftest()
    elif len(sys.argv) > 1:
        res = load_and_audit(Path(sys.argv[1]))
        print(json.dumps(res, indent=2))
    else:
        print(__doc__)
