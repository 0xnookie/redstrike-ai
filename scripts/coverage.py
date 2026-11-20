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

  --mark      Flip ONE ledger category after running it, in place, instead of hand-editing JSON:
              `--mark <id> --status attempted --count N [--note "..."]`. Enforces the status enum
              and the skipped/n-a/blocked-needs-a-reason rule. (Needs --engagement.)

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

ROOT = Path(__file__).resolve().parent.parent
MAP_PATH = ROOT / "skills" / "_contract" / "routing-map.json"
LEDGER_NAME = "coverage_ledger.json"
_OPEN_STATUSES = {"pending"}
_NEED_REASON = {"skipped", "n/a", "blocked"}
_MARK_STATUSES = {"pending", "attempted", "blocked", "skipped", "n/a", "pipeline"}


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
    """Load the recon signal set. Accepts three shapes ('-' = stdin):
      1. a bare JSON list of signal strings:       ["tech:wordpress", "param:injectable"]
      2. a flat object mapping signal -> truthy:    {"tech:wordpress": true, "x": false}
      3. the signals feeder's nested document:      {"signals": [...], "signal_evidence": {...}, ...}
    Shape 3 is what the Redstrike signals feeder emits; without this branch its top-level
    KEYS ("signals", "signal_evidence", ...) were taken as the signal set, silently
    collapsing routing to baseline-only with no error.
    """
    if ref is None:
        return None
    raw = sys.stdin.read() if ref == "-" else Path(ref).read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        sys.exit(f"[!] signals not valid JSON: {e}")
    if isinstance(data, list):
        return {str(x) for x in data}
    if isinstance(data, dict):
        # Nested feeder document: a "signals" list wins over the top-level keys.
        inner = data.get("signals")
        if isinstance(inner, list):
            return {str(x) for x in inner}
        if isinstance(inner, dict):
            return {str(k) for k, v in inner.items() if v}
        # Flat object: {signal: truthy}. Drop known non-signal metadata keys so a
        # mistakenly-flat feeder doc can't smuggle "signal_evidence" etc. in as signals.
        _META = {"_comment", "signal_evidence", "surfaces_ruled_out", "phases"}
        return {k for k, v in data.items() if v and k not in _META}
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


_VC_MOD = None


def _discover_findings(eng: Path):
    """Reuse verify_completion's multi-layout finding discovery (root / per-skill / consolidated) so the
    soft cross-check fires on the REAL per-skill layout (<eng>/*/findings.json), not only a root
    findings.json. Returns a flat list, or None when none/unparseable (cross-check then skipped)."""
    global _VC_MOD
    try:
        if _VC_MOD is None:
            import importlib.util
            p = ROOT / "skills" / "_contract" / "verify_completion.py"
            spec = importlib.util.spec_from_file_location("rs_vc_coverage", p)
            _VC_MOD = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(_VC_MOD)
        findings, _src = _VC_MOD._discover_engagement_findings(eng)
        return findings
    except Exception:  # noqa: BLE001
        return None


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

    # 3. soft cross-check against the engagement's findings — ANY layout (root / per-skill / consolidated),
    #    not just a root findings.json (the real layout is per-skill <eng>/*/findings.json, so the old
    #    root-only check never fired).
    findings = _discover_findings(eng)
    if findings is not None:
        n = len([f for f in findings if isinstance(f, dict)])
        attempted = [c for c in by_id.values() if c.get("status") == "attempted"]
        if n and not attempted:
            warnings.append(f"{n} finding(s) across the engagement but no category is marked 'attempted' "
                            f"(ledger not updated after the run?)")

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
    # close-write: reconcile findings_count + flip pending->attempted from the authoritative findings.
    _led = {"categories": [{"id": "code-audit", "status": "pending", "findings_count": 0},
                           {"id": "xss", "status": "pending", "findings_count": 0}]}
    _chg = reconcile_counts(_led, [{"id": "RS-1", "title": "t"}, {"id": "RS-2", "composite": True}],
                            source_category="code-audit")
    _ca = next(c for c in _led["categories"] if c["id"] == "code-audit")
    assert _ca["status"] == "attempted" and _ca["findings_count"] == 1, _ca  # composite excluded
    _xss = next(c for c in _led["categories"] if c["id"] == "xss")
    assert _xss["status"] == "pending" and _xss["findings_count"] == 0, _xss  # no findings -> untouched
    assert _chg == ["code-audit"], _chg
    # per-skill _rs_source_skill attribution (no source_category needed)
    _led2 = {"categories": [{"id": "idor", "status": "pending", "findings_count": 0}]}
    reconcile_counts(_led2, [{"id": "RS-3", "_rs_source_skill": "idor"}])
    assert _led2["categories"][0]["status"] == "attempted" and _led2["categories"][0]["findings_count"] == 1
    print("coverage.py selftest: OK "
          f"({len(ids)} categories, {len(set(agents))} executors, orphans wired, phases auto-activate)")
    return 0


def mark(eng: Path, cat_id: str, status: str, count=None, note=None, as_json=False,
         escalations=None) -> int:
    """Update one ledger category in place (status / findings_count / reason / escalations).

    This is the first-class way an orchestrator flips an entry after running a
    category, instead of hand-editing the JSON. Enforces the status enum and the
    'skipped/n/a/blocked need a reason' rule the validator checks for.

    `escalations` (a list of escalation.py ladder technique ids) is MERGED into the entry's
    `escalations` list — de-duped, order-preserving — so an executor records which ladder steps it
    climbed on an empty-but-signalled surface. The recall-audit shallow-clear gate reads this to tell an
    exhausted, honest clear from an untrustworthy first-payload clear (fix #3 — persist ladder progress)."""
    ledger_path = eng / LEDGER_NAME
    if not ledger_path.is_file():
        print(f"[!] no {LEDGER_NAME} at {eng} (run: scripts/coverage.py --plan --engagement {eng})")
        return 2
    if status not in _MARK_STATUSES:
        print(f"[!] invalid status {status!r}; choose one of {sorted(_MARK_STATUSES)}")
        return 2
    try:
        led = json.loads(ledger_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"[!] {LEDGER_NAME} invalid JSON: {e}")
        return 2
    cats = led.get("categories", [])
    hit = next((c for c in cats if c.get("id") == cat_id), None)
    if hit is None:
        ids = ", ".join(sorted(str(c.get("id")) for c in cats))
        print(f"[!] no category {cat_id!r} in ledger. known ids: {ids}")
        return 2
    if status in _NEED_REASON and not (note or (hit.get("reason") or "").strip()):
        print(f"[!] status {status!r} requires a reason — pass --note \"...\"")
        return 2
    hit["status"] = status
    if count is not None:
        hit["findings_count"] = count
    if note is not None:
        hit["reason"] = note
    if escalations:
        have = list(hit.get("escalations", []) or [])
        seen = set(have)
        for t in escalations:
            t = str(t).strip()
            if t and t not in seen:
                seen.add(t)
                have.append(t)
        hit["escalations"] = have
    atomic_write(ledger_path, json.dumps(led, indent=2) + "\n")
    if as_json:
        print(json.dumps({"id": cat_id, "status": status,
                          "findings_count": hit.get("findings_count"),
                          "reason": hit.get("reason"),
                          "escalations": hit.get("escalations", [])}, indent=2))
    else:
        tail = (f" findings={count}" if count is not None else "") + (f"  reason={note}" if note else "")
        tail += (f"  escalations+={len(escalations)}" if escalations else "")
        print(f"ok: {cat_id} -> status={status}{tail}")
    return 0


# --- close-write: reconcile the ledger with the authoritative findings at audit close ------------- #
# The silent-green-at-0 failure (shopware-2026-11-19): the autorun crashed, a hunter swarm wrote
# findings.json directly, and nobody flipped the coverage ledger — so every category stayed `pending`
# with findings_count=0 even though 48 findings (code-audit) existed, and the console read a false green.
# `close_write` reconciles the ledger FROM the authoritative findings at close so the ledger reflects
# reality instead of leaving it silent-green.

def _finding_category_counts(findings, *, source_category=None):
    """Count non-composite findings per coverage-category id. Attribution:
      * a per-skill `_rs_source_skill` tag (the per-skill executor layout) maps a finding to that id;
      * `source_category` (e.g. 'code-audit' for a white-box run) claims every otherwise-unattributed
        non-composite finding — in a source engagement all findings come from the code-audit executor.
    Returns {category_id: count}. Pure (no I/O)."""
    from collections import Counter
    counts = Counter()
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        if f.get("composite") or f.get("_composite"):
            continue
        skill = f.get("_rs_source_skill")
        if skill:
            counts[str(skill)] += 1
        elif source_category:
            counts[str(source_category)] += 1
    return dict(counts)


def reconcile_counts(led, findings, *, source_category=None):
    """Update a coverage ledger IN PLACE from the engagement's authoritative findings so it stops reading
    'silent-green at 0' when findings exist. For each category that produced findings: set findings_count
    and, when it is still `pending`/`blocked`, flip it to `attempted` (it clearly ran). A category with no
    findings is left untouched (so the close-write only ever ADDS accuracy, never hides a real gap). Returns
    the list of changed category ids. Pure (operates on the passed dict)."""
    counts = _finding_category_counts(findings, source_category=source_category)
    changed = []
    for c in led.get("categories", []) or []:
        if not isinstance(c, dict):
            continue
        cid = c.get("id")
        n = counts.get(str(cid), 0)
        if n <= 0:
            continue
        dirty = False
        if int(c.get("findings_count", 0) or 0) != n:
            c["findings_count"] = n
            dirty = True
        if str(c.get("status", "")).lower() in ("pending", "blocked"):
            c["status"] = "attempted"
            dirty = True
        if dirty:
            changed.append(cid)
    return changed


def close_write(eng: Path, findings=None, *, source_category=None) -> list:
    """Reconcile coverage_ledger.json from the engagement's authoritative findings at CLOSE and persist it
    (atomic). Best-effort: no ledger / unreadable ledger => no-op ([]). When `findings` is None, discovers
    them the way the completion gate does (root / per-skill / consolidated). Returns changed category ids."""
    ledger_path = eng / LEDGER_NAME
    if not ledger_path.is_file():
        return []
    try:
        led = json.loads(ledger_path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return []
    if findings is None:
        findings = _discover_findings(eng) or []
    changed = reconcile_counts(led, findings, source_category=source_category)
    if changed:
        led["generated_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        atomic_write(ledger_path, json.dumps(led, indent=2) + "\n")
    return changed


def main() -> int:
    ap = argparse.ArgumentParser(description="Redstrike deterministic routing + coverage ledger.")
    ap.add_argument("--plan", action="store_true", help="emit a coverage ledger from map + signals")
    ap.add_argument("--validate", action="store_true", help="validate an engagement's coverage_ledger.json")
    ap.add_argument("--mark", metavar="CATEGORY_ID",
                    help="update one ledger category in the engagement (use with --status; needs --engagement)")
    ap.add_argument("--status", help="new status for --mark: " + "|".join(sorted(_MARK_STATUSES)))
    ap.add_argument("--count", type=int, help="findings_count to set for --mark")
    ap.add_argument("--note", help="reason/note for --mark (required when status is skipped/n/a/blocked)")
    ap.add_argument("--escalations", help="--mark: comma-separated escalation.py ladder technique id(s) tried "
                    "(e.g. derive-not-assume,encoding-ladder); MERGED into the entry's escalations list")
    ap.add_argument("--close", action="store_true",
                    help="reconcile the ledger's findings_count+status from the engagement's findings at "
                         "close (needs --engagement); use --source-category for a white-box run")
    ap.add_argument("--source-category", dest="source_category", default=None,
                    help="--close: attribute every otherwise-unattributed finding to this category id "
                         "(e.g. code-audit for a scope.source engagement)")
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
            atomic_write(out / LEDGER_NAME, json.dumps(led, indent=2) + "\n")
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

    if args.close:
        if not args.engagement:
            ap.error("--close needs --engagement")
        changed = close_write(Path(args.engagement), source_category=args.source_category)
        if args.as_json:
            print(json.dumps({"engagement": args.engagement, "reconciled": changed}, indent=2))
        else:
            if changed:
                print(f"close: reconciled {len(changed)} categor"
                      f"{'y' if len(changed) == 1 else 'ies'} from findings: {', '.join(map(str, changed))}")
            else:
                print("close: no coverage categories to reconcile (no ledger, or no findings matched a category)")
        return 0

    if args.mark:
        if not args.engagement:
            ap.error("--mark needs --engagement")
        if not args.status:
            ap.error("--mark needs --status (" + "|".join(sorted(_MARK_STATUSES)) + ")")
        esc = [t.strip() for t in (args.escalations or "").split(",") if t.strip()] or None
        return mark(Path(args.engagement), args.mark, args.status,
                    args.count, args.note, args.as_json, escalations=esc)

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
