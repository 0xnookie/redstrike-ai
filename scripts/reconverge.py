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
COVERAGE_LEDGER = "coverage_ledger.json"
SURFACE_LEDGER = "surface_ledger.json"
INBOX = "reconvergence/inbox.jsonl"  # executors append observation records here
REJECTED_INBOX = "reconvergence/inbox.rejected.jsonl"  # quarantined invalid record parts (ingest safety)
CONTENT_FOLLOWUPS = "reconvergence/content_followups.jsonl"  # content-kind discoveries routed to content-discovery (fix #5)

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


def _signal_vocab() -> set:
    """The CLOSED signal vocabulary (routing-map.json `signals` keys). Empty => unreadable (fail-open)."""
    m = _read_json(ROOT / "skills" / "_contract" / "routing-map.json") or {}
    return set((m.get("signals") or {}).keys())


def _load_surface_mod():
    try:
        import surface as _sf  # scripts/ on sys.path
        return _sf
    except ImportError:  # pragma: no cover - path fallback
        import importlib.util as _ilu
        _sp = _ilu.spec_from_file_location("surface", str(ROOT / "scripts" / "surface.py"))
        _sf = _ilu.module_from_spec(_sp)
        _sp.loader.exec_module(_sf)
        return _sf


def _surface_kinds() -> set:
    """The CLOSED testable surface-kind enum (surface.py VALID_KINDS; falls back to the schema). Empty => fail-open."""
    try:
        return set(_load_surface_mod().VALID_KINDS)
    except Exception:  # pragma: no cover
        s = _read_json(ROOT / "skills" / "_contract" / "surface_ledger.schema.json") or {}
        kind = (((s.get("$defs") or {}).get("surface") or {}).get("properties") or {}).get("kind") or {}
        return set(kind.get("enum") or [])


def _followup_routes() -> dict:
    """kind -> recon feeder for the non-testable 'follow-up' kinds (surface.FOLLOWUP_ROUTES; e.g.
    content -> content-discovery). A content-kind discovery is NOT corruption and NOT a ledger element —
    it ROUTES BACK to content-discovery for URL/object-ref extraction (fix #5)."""
    try:
        return dict(_load_surface_mod().FOLLOWUP_ROUTES)
    except Exception:  # pragma: no cover
        return {"content": "content-discovery"}


def _read_inbox_raw(eng: Path) -> list:
    """Raw inbox records (one JSON object per line); malformed lines are dropped."""
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


def split_observations(records, vocab, kinds, followup_routes=None):
    """Validate raw inbox records against the signal vocab + surface-kind enum (pure, no I/O).

    Returns (clean, rejections, followups). Each clean observation keeps ONLY in-vocab signals and
    valid-kind, non-empty surface items; `rejections` has one entry per source record that carried anything
    GENUINELY invalid (a typo signal, an unknown surface kind), naming what was dropped and why; `followups`
    holds recognized non-testable 'follow-up' discoveries (a `content` sitemap/robots/API-schema) routed BACK
    to content-discovery for URL/object-ref extraction (fix #5) — these are neither folded into the ledgers
    nor quarantined as garbage. An empty `vocab`/`kinds` means 'cannot check' → fail-open (keep all)."""
    froutes = _followup_routes() if followup_routes is None else dict(followup_routes)
    clean, rejections, followups = [], [], []
    for rec in records or []:
        if not isinstance(rec, dict):
            rejections.append({"source": "?", "reasons": ["record is not a JSON object"], "record": rec})
            continue
        src = rec.get("source", "hunt")
        good_sig, bad_sig = [], []
        for s in rec.get("signals", []) or []:
            (good_sig if (not vocab or str(s) in vocab) else bad_sig).append(str(s))
        good_surf, bad_surf = [], []
        for item in rec.get("surface", []) or []:
            k = (item or {}).get("kind")
            v = str((item or {}).get("value", "")).strip()
            if k and v and k in froutes:
                followups.append({"kind": k, "value": v,
                                  "discovered_by": (item or {}).get("discovered_by", src),
                                  "route_to": froutes[k], "action": "extract URLs + object references"})
            elif k and v and (not kinds or k in kinds):
                good_surf.append(item)
            else:
                bad_surf.append(item)
        if bad_sig or bad_surf:
            reasons = []
            if bad_sig:
                reasons.append("out-of-vocab signal(s): " + ", ".join(sorted(set(bad_sig))))
            if bad_surf:
                reasons.append("invalid surface kind(s): "
                               + ", ".join(sorted({str((b or {}).get('kind')) for b in bad_surf})))
            rejections.append({"source": src, "reasons": reasons,
                               "rejected_signals": bad_sig, "rejected_surface": bad_surf})
        if good_sig or good_surf:
            clean.append({"source": src, "signals": good_sig, "surface": good_surf})
    return clean, rejections, followups


# --- write-time inbox validator (QW-2): reject prose at the moment an executor appends --------------- #
# The root cause of the inbox.rejected.jsonl pollution (20min retro, incident 3): executors stuffed
# CLEAN/residual PROSE into the inbox -- free text in `signals` (not the closed vocab) and NOTE-shaped
# surface kinds (`note`/`behavior`/`path`) -- because the inbox had no write-time schema AND a class-clean
# note had no legitimate home. `split_observations` already HARD-fails the report on exactly these at the
# coordination-integrity gate, but only DOWNSTREAM, after the bad line is on disk. `--append` runs that same
# check at WRITE time: a clean record is appended, a dirty one is REFUSED (nothing written) and the caller
# is told the closed vocab AND -- for a note/residual -- WHERE the note actually belongs (a coverage mark).

# Surface kinds that are really a NOTE in disguise -- the exact `kind:note`/`kind:behavior`/`kind:path`
# pollution. These never belong in the inbox; they are redirected to a coverage --depth-note / skip.
_NOTE_LIKE_KINDS = {"note", "behavior", "path", "residual", "clean", "comment", "observation", "status"}
_RESIDUAL_WORDS = ("clean", "residual", "not demonstrable", "n/a", "tested", "nothing", "no finding")


def build_record(source: str, signals, surfaces) -> dict:
    """Build one inbox observation record from CLI parts (pure). `surfaces` is a list of (kind, value)."""
    return {"source": source or "hunt",
            "signals": [str(s) for s in (signals or [])],
            "surface": [{"kind": k, "value": v} for (k, v) in (surfaces or [])]}


def _prose_signals(signals) -> list:
    """Signals that are PROSE, not a `token:token` vocab tag -- a space, or no ':' at all. Caught
    STRUCTURALLY (independent of the vocab) so a prose signal is refused even if the routing map is
    unreadable and `split_observations` would fail-open and keep it."""
    bad = []
    for s in signals or []:
        s = str(s)
        if (" " in s) or (":" not in s) or any(w in s.lower() for w in _RESIDUAL_WORDS):
            bad.append(s)
    return bad


def classify_append(record, vocab, kinds, followup_routes=None) -> dict:
    """Decide whether ONE record may be appended to the inbox (pure, no I/O). Returns
    {ok, rejections, prose_signals, note_kinds, has_payload}. ok is True only when the record carries
    payload and nothing is rejected / prose / note-shaped."""
    clean, rejections, _followups = split_observations([record], vocab, kinds, followup_routes)
    prose = _prose_signals(record.get("signals"))
    note_kinds = sorted({str((it or {}).get("kind")) for it in (record.get("surface") or [])
                         if str((it or {}).get("kind", "")).lower() in _NOTE_LIKE_KINDS})
    has_payload = bool(record.get("signals")) or bool(record.get("surface"))
    ok = has_payload and not rejections and not prose and not note_kinds
    return {"ok": ok, "rejections": rejections, "prose_signals": prose,
            "note_kinds": note_kinds, "has_payload": has_payload}


def _coverage_redirect(source: str) -> str:
    """The redirect emitted when a record is really a class-clean / residual NOTE: a note has NO home in the
    reconvergence inbox -- it belongs on the coverage ledger. Stops the behaviour at the source instead of
    just blocking it (the `kind:note` pollution root cause)."""
    cat = source or "<class>"
    return ("this looks like a class-clean / residual NOTE, which has NO home in the reconvergence inbox "
            "(the inbox is for new SIGNALS + testable SURFACE only). Record it on the coverage ledger instead:\n"
            f"  - a class-clean with depth evidence:  python scripts/coverage.py --mark {cat} --status attempted "
            f"--count 0 --depth-note \"<what the depth work observed>\" --engagement <dir>\n"
            f"  - a residual / deferred lead:          python scripts/coverage.py --mark {cat} --status skipped "
            f"--note \"<why deferred / not demonstrable here>\" --engagement <dir>\n"
            "  Do NOT put prose into `signals` or use a note-shaped surface kind.")


def append_observation(eng: Path, source: str, signals, surfaces) -> tuple:
    """Validate ONE record at WRITE time and, only if all-clean, append it to reconvergence/inbox.jsonl.
    Returns (rc, lines). rc 0 = appended; rc 2 = refused (nothing written) -- lines then carry the closed
    vocab / kind enum, the offending token(s), and (for a note/residual) the coverage redirect."""
    record = build_record(source, signals, surfaces)
    vocab, kinds = _signal_vocab(), _surface_kinds()
    res = classify_append(record, vocab, kinds)
    if res["ok"]:
        inbox = eng / INBOX
        inbox.parent.mkdir(parents=True, exist_ok=True)
        with open(inbox, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
        return 0, [f"[reconverge] appended 1 observation from {record['source']} to {INBOX} "
                   f"(signals={record['signals']}, surface={[s['value'] for s in record['surface']]})"]
    lines = ["[reconverge] REFUSED to append — the record is not clean; NOTHING was written."]
    if not res["has_payload"]:
        lines.append("  reason: empty record (pass at least one --signal or --surface)")
    for s in res["prose_signals"]:
        lines.append(f"  reason: signal {s!r} is PROSE, not a `token:token` vocab tag")
    for r in res["rejections"]:
        for reason in r.get("reasons", []):
            lines.append(f"  reason: {reason}")
    if res["note_kinds"]:
        lines.append(f"  reason: note-shaped surface kind(s) {res['note_kinds']} are not testable surface")
    # always show the closed vocabularies so the caller can self-correct
    if vocab:
        lines.append(f"  allowed signal vocab ({len(vocab)}): {', '.join(sorted(vocab))}")
    if kinds:
        lines.append(f"  allowed surface kinds: {', '.join(sorted(kinds))}")
    # redirect a note/residual to its real home (the coverage ledger)
    if res["prose_signals"] or res["note_kinds"] or any(
            w in (s or "").lower() for s in (record.get("signals") or []) for w in _RESIDUAL_WORDS):
        lines.append("  -> " + _coverage_redirect(record["source"]))
    return 2, lines


def load_observations(eng: Path) -> list:
    """Read + VALIDATE the inbox: returns observations with ONLY in-vocab signals and valid-kind surface,
    so an invalid token (a typo signal, an unknown surface kind) is never folded into the ledgers. The read
    is pure — rejected parts are quarantined and content follow-ups rerouted by `ingest_inbox`."""
    clean, _rej, _fu = split_observations(_read_inbox_raw(eng), _signal_vocab(), _surface_kinds())
    return clean


def ingest_inbox(eng: Path) -> list:
    """The real ingest (called by --plan/--apply): read the inbox, QUARANTINE every genuinely-invalid record
    part to reconvergence/inbox.rejected.jsonl (loud stderr), ROUTE content-kind discoveries to
    reconvergence/content_followups.jsonl for content-discovery to re-extract (fix #5), and return the cleaned
    observations. Both sidecars are rewritten to reflect the CURRENT inbox (idempotent)."""
    records = _read_inbox_raw(eng)
    clean, rejections, followups = split_observations(records, _signal_vocab(), _surface_kinds())
    sidecar = eng / REJECTED_INBOX
    if rejections:
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        lines = []
        for r in rejections:
            lines.append(json.dumps({**r, "quarantined_at": stamp}))
            print(f"[reconverge] REJECTED invalid inbox record from {r.get('source', '?')}: "
                  f"{'; '.join(r.get('reasons', []))} — quarantined to {REJECTED_INBOX}, NOT folded "
                  f"into coverage_ledger.signals_used / the surface ledger", file=sys.stderr)
        atomic_write(sidecar, "\n".join(lines) + "\n")
    fu_path = eng / CONTENT_FOLLOWUPS
    if followups:
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        atomic_write(fu_path, "\n".join(json.dumps({**f, "queued_at": stamp}) for f in followups) + "\n")
        print(f"[reconverge] ROUTED {len(followups)} content discovery(ies) "
              f"({', '.join(sorted({f['value'] for f in followups})[:4])}) to content-discovery for "
              f"URL/object-ref extraction — queued in {CONTENT_FOLLOWUPS} (not a surface-ledger element, "
              f"not quarantined)", file=sys.stderr)
    return clean


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

    # 8) Ingest validation: an out-of-vocab signal is REJECTED, a valid surface item survives, and a
    #    `content` discovery is ROUTED to content-discovery (fix #5), not quarantined as garbage.
    vocab = {"param:url-fetching", "asset:cloud"}
    kinds = {"param", "endpoint"}
    froutes = {"content": "content-discovery"}
    recs = [{"source": "pp/open-redirect", "signals": ["sink:dom-backlink", "param:url-fetching"],
             "surface": [{"kind": "param", "value": "from"}, {"kind": "content", "value": "/sitemap.xml"}]}]
    clean, rej, fu = split_observations(recs, vocab, kinds, froutes)
    assert len(clean) == 1 and clean[0]["signals"] == ["param:url-fetching"], clean
    assert [s["value"] for s in clean[0]["surface"]] == ["from"], clean
    assert len(rej) == 1 and "sink:dom-backlink" in rej[0]["rejected_signals"]
    assert not rej[0]["rejected_surface"], "content is a followup, not rejected garbage"
    assert len(fu) == 1 and fu[0]["value"] == "/sitemap.xml" and fu[0]["route_to"] == "content-discovery"
    # a TRULY out-of-enum kind (typo) is still rejected.
    recs_bad = [{"source": "x", "surface": [{"kind": "contnet", "value": "/x"}]}]
    _c, rb, fb = split_observations(recs_bad, vocab, kinds, froutes)
    assert not fb and rb and any(b.get("kind") == "contnet" for b in rb[0]["rejected_surface"])
    # fail-open: an empty vocab/kinds (unreadable map) keeps signals; content is still a followup.
    clean2, rej2, fu2 = split_observations(recs, set(), set(), froutes)
    assert not rej2 and clean2[0]["signals"] == ["sink:dom-backlink", "param:url-fetching"]
    assert len(fu2) == 1
    # a record with ONLY invalid parts yields no clean observation (so it can't trigger the reconverge gate).
    only_bad = [{"source": "x", "signals": ["totally:made-up"]}]
    cb, rb2, _fb = split_observations(only_bad, vocab, kinds, froutes)
    assert cb == [] and rb2 and "totally:made-up" in rb2[0]["rejected_signals"]

    # 9) --append write-time classifier (QW-2): a clean record is appendable; prose signals + note-shaped
    #    surface kinds are refused (they belong on a coverage mark, not the inbox).
    clean_rec = build_record("ssrf", ["param:url-fetching"], [("endpoint", "http://10.0.0.5/")])
    r_ok = classify_append(clean_rec, vocab, kinds, froutes)
    assert r_ok["ok"] and not r_ok["rejections"] and not r_ok["prose_signals"], r_ok
    # a PROSE signal is caught structurally even when the vocab can't be read (fail-open must NOT keep it).
    prose_rec = build_record("websocket", ["websocket class CLEAN []"], [])
    r_prose = classify_append(prose_rec, set(), set(), froutes)
    assert not r_prose["ok"] and r_prose["prose_signals"], r_prose
    # a note-shaped surface kind is refused.
    note_rec = build_record("auth", [], [("note", "RESIDUAL — not demonstrable here")])
    r_note = classify_append(note_rec, vocab, kinds, froutes)
    assert not r_note["ok"] and "note" in r_note["note_kinds"], r_note
    # an out-of-vocab (non-prose) signal is refused via split_observations.
    typo_rec = build_record("x", ["param:injectible"], [])
    r_typo = classify_append(typo_rec, vocab, kinds, froutes)
    assert not r_typo["ok"] and r_typo["rejections"], r_typo
    # an empty record has no payload -> not appendable.
    assert not classify_append(build_record("x", [], []), vocab, kinds, froutes)["ok"]

    print("reconverge selftest: OK")


def main() -> int:
    ap = argparse.ArgumentParser(description="Redstrike finding->recon re-convergence controller.")
    ap.add_argument("--plan", action="store_true", help="compute a re-convergence pass from the inbox + ledgers")
    ap.add_argument("--apply", action="store_true", help="plan, then fold the delta back into the ledgers")
    ap.add_argument("--validate", action="store_true", help="exit non-zero if the inbox hasn't re-converged")
    ap.add_argument("--append", action="store_true",
                    help="WRITE-TIME inbox validator: build one observation from --source/--signal/--surface, "
                         "validate it against the signal vocab + surface-kind enum, and append it to "
                         "reconvergence/inbox.jsonl ONLY if clean (else write nothing, exit non-zero). "
                         "A prose signal / note-shaped surface is refused + redirected to a coverage mark.")
    ap.add_argument("--source", help="--append: the emitting skill/class (the record's `source`)")
    ap.add_argument("--signal", action="append", dest="signals", default=[],
                    help="--append: a `token:token` signal from the routing vocab (repeatable)")
    ap.add_argument("--surface", action="append", dest="surfaces", default=[],
                    help="--append: a testable surface element as kind=value (repeatable), e.g. endpoint=https://api.x/y")
    ap.add_argument("--engagement", help="engagement dir")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return 0
    if not args.engagement:
        ap.error("choose --plan/--apply/--validate/--append with --engagement, or --selftest")
    eng = Path(args.engagement)

    if args.append:
        surfaces = []
        for tok in args.surfaces or []:
            if "=" not in tok:
                ap.error(f"--surface must be kind=value, got {tok!r}")
            k, v = tok.split("=", 1)
            surfaces.append((k.strip(), v.strip()))
        rc, lines = append_observation(eng, args.source, args.signals, surfaces)
        if args.as_json:
            print(json.dumps({"engagement": str(eng), "appended": rc == 0, "messages": lines}, indent=2))
        else:
            for l in lines:
                print(l)
        return rc

    if args.plan or args.apply:
        ingest_inbox(eng)  # quarantine invalid inbox records (loud) BEFORE routing anything
        plan = load_and_plan(eng)
        if args.apply and not plan["converged"]:
            cov = _read_json(eng / COVERAGE_LEDGER) or {}
            surf = _read_json(eng / SURFACE_LEDGER)
            apply_plan(cov, surf if surf is not None else {"engagement": eng.name, "surfaces": []}, plan)
            atomic_write(eng / COVERAGE_LEDGER, json.dumps(cov, indent=2) + "\n")
            if surf is not None:
                atomic_write(eng / SURFACE_LEDGER, json.dumps(surf, indent=2) + "\n")
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
