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


# Server-side interpreter-sink signals. A category gated by one of these (the `injection` family:
# ssti / command-injection / deserialization) can only be ROUTED when a white-box source-audit (or a
# limited js-analysis pass) emits the signal — black-box recon cannot SEE a template/command/deserializer
# sink. So a no-signal skip of such a class in a black-box run is recon BLINDNESS, not a proven absence.
_SINK_SIGNALS = frozenset({"sink:template", "sink:command"})


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
            # Black-box sink blindness (fix #4): a server-side-sink class skipped with NO black-box producer
            # for its sink signal is recon blindness, not a proven negative — a MEDIUM gap to probe behaviorally.
            sink_trigs = trig.get(cid, set()) & _SINK_SIGNALS
            if sink_trigs and "source:available" not in sig and not (sink_trigs & sig):
                gaps.append({"category": cid, "type": "sink-class-skipped-blackbox", "severity": "medium",
                             "detail": ("server-side-sink class skipped with no black-box producer for its "
                                        "sink signal(s) " + ", ".join(sorted(sink_trigs))
                                        + " — black-box recon cannot see a template/command/deserializer sink, "
                                        "so this skip is recon blindness, not a proven absence"),
                             "suggested_action": ("probe it black-box on injectable params (behavioural / timing "
                                                  "/ OOB), or run source-audit (white-box) to emit the sink signal")})

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
    res = audit(led.get("categories", []), _load_signals(eng), mp.get("categories", []), escalations)
    # fold in surface-coverage gaps (fix #5): discovered-but-untested surface elements are concrete misses
    surf_p = eng / "surface_ledger.json"
    if surf_p.is_file():
        try:
            import surface as _sf  # scripts/ on sys.path
        except ImportError:  # pragma: no cover
            import importlib.util as _ilu
            _sp = _ilu.spec_from_file_location("surface", str(_repo_root() / "scripts" / "surface.py"))
            _sf = _ilu.module_from_spec(_sp); _sp.loader.exec_module(_sf)
        try:
            sgaps = _sf.surface_gaps(json.loads(surf_p.read_text(encoding="utf-8")))
        except Exception:  # noqa: BLE001
            sgaps = []
        if sgaps:
            res["gaps"] = sgaps + res["gaps"]
            res["summary"]["total"] += len(sgaps)
            res["summary"]["high"] += sum(1 for g in sgaps if g["severity"] == "high")
            res["summary"].setdefault("by_type", {})["untested-surface"] = len(sgaps)
    return res


# --- honest-accept writer (recall fix: close the gameable-vs-honest asymmetry) ----------------------- #
# Clearing a shallow-clear by HAND (coverage.py --mark attempted --count 0 --escalations <full ladder>)
# is deterministic, reason-free, and the fabrication the safety classifier blocks — so the honest path was
# the higher-friction one. This writer makes the HONEST close first-class and un-gameable: it records an
# accept ONLY for a gap the deterministic engine actually flags, ONLY with a named environmental blocker
# from a CLOSED vocabulary, and (for a shallow-clear) ONLY alongside the escalation techniques that
# genuinely ran — so an accept auditably states "couldn't, because X", never "tried, trust us".
#
# CLOSED blocker vocabulary: the named environmental reasons a gap can be genuinely unclosable in-scope.
_BLOCKER_VOCAB = {
    "no-oob-collaborator",   # no out-of-band collaborator/canary in scope — blind/OOB proof impossible
    "single-identity",       # only one test identity — a cross-user authz miss can't be demonstrated
    "browser-declined",      # no real-browser render available — client-side (DOM/reflected) detection blocked
    "captcha-gated",         # the surface sits behind a CAPTCHA that can't be solved in-scope
    "opaque-session",        # the session/token is opaque/unforgeable with the access available
    "no-sink-surface",       # black-box: no reachable template/command/deserializer sink to probe
    "destructive-withheld",  # the only remaining escalation is destructive and withheld by the RoE
    "no-mailbox",            # no mailbox/inbox to receive a reset/confirmation and complete the flow
}


def _parse_csv(val) -> list:
    return [t.strip() for t in str(val or "").split(",") if t.strip()]


def write_accept(eng: Path, accept_id: str, *, blockers, ladder_run, reason) -> tuple:
    """Record an honest recall-audit accept into ``<eng>/reviews/recall_audit_accepts.json`` in the LIST
    shape ``verify_completion._recall_accepts`` reads (``[{"id","reason","blocker","ladder_run"}]``) — the
    reader keys on ``id``+``reason`` and tolerates the extra fields, so this ENRICHES the record without a
    reader change. Returns ``(ok, message)``. Un-gameable guard rails (checked in cost order — cheap
    validations before the disk read):

      1. ``accept_id`` must be ``<type>:<category>``.
      2. ``reason`` must be non-empty (a blank reason is not an accept — the reader drops it anyway).
      3. ``--blocker`` is REQUIRED, from the CLOSED ``_BLOCKER_VOCAB`` — an accept must NAME why the gap is
         unclosable; "we just didn't" is rejected.
      4. the gap must ACTUALLY be flagged by the deterministic engine for THIS engagement (no pre-stamping
         a non-gap).
      5. a ``shallow-clear`` accept REQUIRES ``--ladder-run`` validated against ``escalation.ladder_for`` —
         real technique ids that genuinely ran, recorded separately from the residual blocker.
    """
    if ":" not in accept_id:
        return False, (f"--accept must be '<type>:<category>' (e.g. shallow-clear:sqli); got {accept_id!r}")
    gtype, cat = (p.strip() for p in accept_id.split(":", 1))
    if not gtype or not cat:
        return False, (f"--accept must be '<type>:<category>' (e.g. shallow-clear:sqli); got {accept_id!r}")

    if not (reason and str(reason).strip()):
        return False, "--reason is required and must be non-empty (state why this gap is genuinely unclosable here)"

    if not blockers:
        return False, ("--blocker is required: an accept must name the environmental blocker that made the gap "
                       f"unclosable (closed vocab: {', '.join(sorted(_BLOCKER_VOCAB))}). An accept states "
                       "'couldn't, because X' — never 'tried, trust us'.")
    bad = [b for b in blockers if b not in _BLOCKER_VOCAB]
    if bad:
        return False, (f"unknown --blocker value(s) {bad}; choose from the closed vocab: "
                       f"{', '.join(sorted(_BLOCKER_VOCAB))}")

    res = load_and_audit(eng)
    gaps = res.get("gaps", [])
    match = next((g for g in gaps if g.get("category") == cat and g.get("type") == gtype), None)
    if match is None:
        flagged = sorted({f"{g.get('type')}:{g.get('category')}" for g in gaps})
        return False, (f"the deterministic recall engine does not currently flag {accept_id!r} for this "
                       f"engagement — nothing to accept (currently flagged: {flagged or ['none']}). Re-run the "
                       "class or correct the type:category; an accept cannot pre-stamp a non-gap.")

    if gtype == "shallow-clear":
        valid = _esc.ladder_for(cat)
        if not ladder_run:
            return False, ("--ladder-run is required for a shallow-clear accept: record the escalation "
                           f"technique ids that genuinely ran (from {cat}'s ladder: {', '.join(valid)}). "
                           "An honest clear separates what ran from the residual blocker.")
        bad_l = [t for t in ladder_run if t not in set(valid)]
        if bad_l:
            return False, (f"--ladder-run technique(s) {bad_l} are not in {cat}'s escalation ladder "
                           f"({', '.join(valid)}) — record the REAL technique ids that ran.")

    entry = {"id": accept_id, "reason": str(reason).strip(), "blocker": list(blockers)}
    if ladder_run:
        entry["ladder_run"] = list(ladder_run)

    p = eng / "reviews" / "recall_audit_accepts.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    existing = []
    if p.is_file():
        try:
            cur = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            cur = None
        if isinstance(cur, list):
            existing = [e for e in cur if isinstance(e, dict)]
        elif isinstance(cur, dict):  # migrate the legacy dict shape to the list shape (enrich, don't break)
            for k, v in cur.items():
                r = v if isinstance(v, str) else (v.get("reason") if isinstance(v, dict) else "")
                existing.append({"id": str(k), "reason": r})
    existing = [e for e in existing if e.get("id") != accept_id]  # idempotent: replace a prior accept
    existing.append(entry)
    p.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
    return True, f"recorded accept {accept_id} (blocker={','.join(blockers)}) -> {p}"


def selftest() -> None:
    mapc = [
        {"id": "xss", "triggers": ["sink:html-reflect", "sink:dom", "param:any"]},
        {"id": "sqli", "triggers": ["param:injectable"]},
        {"id": "ssrf", "triggers": ["param:url-fetching"]},
        {"id": "injection", "triggers": ["sink:template", "sink:command", "param:injectable"]},
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

    # 6b) sink-class black-box blindness (fix #4): a server-side-sink class (injection) skipped in a
    #     BLACK-BOX run (no source:available) with no sink signal -> MEDIUM gap (recon can't see the sink).
    led_sink = [{"id": "injection", "status": "skipped",
                 "reason": "no template/command/deserialization sink surfaced", "findings_count": 0}]
    r = audit(led_sink, set(), mapc)
    assert r["gaps"][0]["type"] == "sink-class-skipped-blackbox" and r["gaps"][0]["severity"] == "medium", r
    # WHITE-BOX (source:available present): source-audit could emit the sink signal, so a skip is trustworthy.
    assert audit(led_sink, {"source:available"}, mapc)["summary"]["total"] == 0
    # a non-sink class skipped with a good reason and no signal stays silent (no false positive).
    assert audit([{"id": "ssrf", "status": "skipped", "reason": "no URL-fetching parameter surfaced"}],
                 set(), mapc)["summary"]["total"] == 0

    # 7) pending at close -> HIGH gap; a found class -> no gap; ranking puts high first.
    led5 = [{"id": "sqli", "status": "pending"},
            {"id": "xss", "status": "attempted", "findings_count": 3, "triggers_matched": ["sink:dom"]},
            {"id": "secrets", "status": "skipped", "reason": "x"}]
    r = audit(led5, set(), mapc)
    types = {g["type"] for g in r["gaps"]}
    assert "pending-at-close" in types
    assert all(g["category"] != "xss" for g in r["gaps"]), "a class with findings is not a gap"
    assert r["gaps"][0]["severity"] == "high"

    # 8) honest-accept writer refusals that fire BEFORE any disk read (un-gameable guard rails):
    ok, msg = write_accept(Path("."), "sqli", blockers=["opaque-session"], ladder_run=[], reason="r")
    assert not ok and "<type>:<category>" in msg, msg                 # bad id shape
    ok, msg = write_accept(Path("."), "shallow-clear:sqli", blockers=[], ladder_run=[], reason="r")
    assert not ok and "--blocker is required" in msg, msg             # no named blocker
    ok, msg = write_accept(Path("."), "shallow-clear:sqli", blockers=["totally-made-up"],
                           ladder_run=[], reason="r")
    assert not ok and "unknown --blocker" in msg, msg                 # blocker off the closed vocab
    ok, msg = write_accept(Path("."), "shallow-clear:sqli", blockers=["opaque-session"],
                           ladder_run=[], reason="   ")
    assert not ok and "--reason is required" in msg, msg              # blank reason

    print("recall_audit selftest: OK")


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        description="Redstrike recall-audit — the 'what did we miss?' altitude, and the honest-accept writer.")
    ap.add_argument("engagement", nargs="?", help="engagement dir to audit (dump ranked recall gaps as JSON)")
    ap.add_argument("--selftest", action="store_true", help="run the module selftest")
    ap.add_argument("--accept", metavar="TYPE:CATEGORY",
                    help="record an honest accept for a genuinely-unclosable recall gap (the first-choice "
                         "honest close); requires --engagement, --blocker and --reason")
    ap.add_argument("--engagement", dest="engagement_opt", help="engagement dir (used with --accept)")
    ap.add_argument("--blocker", help="comma-separated environmental blocker(s) from the closed vocab "
                                      "(REQUIRED with --accept)")
    ap.add_argument("--ladder-run", dest="ladder_run",
                    help="comma-separated escalation technique ids that genuinely ran "
                         "(REQUIRED for a shallow-clear accept)")
    ap.add_argument("--reason", help="why this gap is genuinely unclosable here (REQUIRED with --accept)")
    args = ap.parse_args(argv)

    if args.selftest:
        selftest()
        return 0
    if args.accept:
        eng = Path(args.engagement_opt or args.engagement or ".")
        if not eng.is_dir():
            ap.error(f"engagement dir not found: {eng}")
        ok, msg = write_accept(eng, args.accept.strip(), blockers=_parse_csv(args.blocker),
                               ladder_run=_parse_csv(args.ladder_run), reason=args.reason or "")
        print(msg)
        return 0 if ok else 2
    if args.engagement:
        print(json.dumps(load_and_audit(Path(args.engagement)), indent=2))
        return 0
    print(__doc__)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
