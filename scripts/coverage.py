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
import time
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


# --- concurrent-writer safety -------------------------------------------------------------------- #
# The hunt now fans out as CONCURRENT subagents that update this ledger simultaneously. `atomic_write`
# already guarantees a reader never sees a torn file, but two writers that each read-then-write would
# still clobber each other (last-write-wins drops the first writer's mark). A per-file advisory lock
# serializes the read-modify-write so every concurrent mark/close/merge survives. coverage.py stays the
# SOLE reconciler — this only makes coverage.py's OWN writes to its ledger mutually exclusive.
class _FileLock:
    """Best-effort cross-process advisory lock via an exclusive lock file (stdlib only; no fcntl/msvcrt,
    so Windows + Linux/WSL behave identically). Spins up to ``timeout``; a lock older than ``stale`` is
    treated as abandoned (the holder crashed) and broken. If it still can't acquire by the deadline it
    proceeds anyway (degraded last-write-wins) rather than deadlock the hunt — ``atomic_write`` keeps the
    file un-torn either way."""

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


ROOT = Path(__file__).resolve().parent.parent
MAP_PATH = ROOT / "skills" / "_contract" / "routing-map.json"
LEDGER_NAME = "coverage_ledger.json"
_OPEN_STATUSES = {"pending"}
_NEED_REASON = {"skipped", "n/a", "blocked"}
_MARK_STATUSES = {"pending", "attempted", "blocked", "skipped", "n/a", "pipeline"}

# --- DEPTH-SUBSTANCE BAR (Trust: no rubber-stamped recall) ------------------------------------------ #
# META-LESSON: "a step/gate the workflow can route around is not real." A bare `--mark <id> --status
# attempted --count 0` can be RUBBER-STAMPED — "attempted" alone does not PROVE the surface was actually
# worked, so a shallow pass masquerades as covered and the completion gate passes. The depth-substance bar
# closes that: an `attempted` category with ZERO findings (a "clear") may only count as covered when the
# mark carries real depth evidence — enough distinct probe ATTEMPTS and technique VARIANTS, plus a
# differential/blocker NOTE of real length OR an evidence POINTER. A category that produced >=1 finding is
# self-evidently substantiated (the finding is the proof) and is exempt. The thresholds are per-class,
# configured in routing-map.json's `depth_substance` block; _DEFAULT_DEPTH is only the fallback when that
# block is absent. The bar is enforced in TWO places that can't be routed around:
#   * mark(): records the depth payload and computes `depth_substantiated`; refuses the flip under
#             --require-depth (the flip then simply never lands, so the category STAYS re-drivable).
#   * validate() (the completion gate): RECOMPUTES substance from the entry's own fields, so even a
#             hand-edited `"status":"attempted"` with no depth is REJECTED and re-driven — never counted.
_MIN_DEPTH_NOTE = 24                                 # chars — a differential/blocker note "of real length"
_DEFAULT_DEPTH = {"min_attempts": 3, "min_variants": 2}  # fallback when the map declares no depth_substance


def _safe_map() -> dict:
    """Load the routing map for threshold lookups WITHOUT ever aborting the caller — load_map() sys.exits on
    a missing/invalid map, but a depth-threshold read must degrade to the built-in default, not kill a mark.
    Returns {} on any failure (depth_thresholds then falls back to _DEFAULT_DEPTH)."""
    try:
        return load_map()
    except SystemExit:
        return {}
    except Exception:  # noqa: BLE001
        return {}


# A `blocked` row whose reason is sourced from a WHOLE-SURFACE environmental block (the diagnostics
# transport-block auto-populate writes `reason = "transport: WAF block_rate ... on <host> (...)"`) is NOT
# the per-leg family mask this granularity rule targets: when the entire host/WAF is down, NO sibling
# sub-surface was reachable, so a family block there cannot hide an untested-but-reachable sibling. Such a
# disclosed whole-surface block is exempt from the sub-surface-enumeration requirement.
def _is_whole_surface_block(entry: dict) -> bool:
    return str((entry or {}).get("reason") or "").strip().lower().startswith("transport:")


def family_agents(m: dict, cat_id: str) -> list:
    """The sub-agent ids of ``cat_id`` when it is a ``pattern: family`` category with MORE THAN ONE
    sub-agent (e.g. auth -> [auth-bypass, jwt, oauth]; sqli -> [sqli-inband, sqli-blind]) — else []. These
    are the categories whose single `blocked` row can silently absorb an untested in-scope sibling
    sub-surface; a single-agent category can't mask a sibling. Pure; tolerant of a missing/malformed map."""
    for c in (m or {}).get("categories", []) or []:
        if c.get("id") == cat_id and c.get("pattern") == "family":
            agents = [str(a) for a in (c.get("agents") or []) if str(a).strip()]
            if len(agents) > 1:
                return agents
    return []


def depth_thresholds(m: dict, cat_id: str) -> dict:
    """The (min_attempts, min_variants) a zero-finding `attempted` clear must prove for ``cat_id``: the map's
    ``depth_substance.default`` overlaid by any ``depth_substance.classes[cat_id]`` override, starting from
    _DEFAULT_DEPTH. Pure; tolerant of a missing/malformed block (falls back to the default)."""
    out = dict(_DEFAULT_DEPTH)
    cfg = (m or {}).get("depth_substance") or {}
    for layer in (cfg.get("default"), (cfg.get("classes") or {}).get(cat_id)):
        if isinstance(layer, dict):
            for k in ("min_attempts", "min_variants"):
                v = layer.get(k)
                if isinstance(v, int) and not isinstance(v, bool) and v >= 0:
                    out[k] = v
    return out


def _variant_set(entry: dict) -> set:
    """The distinct technique variants a category has recorded — the UNION of the new ``variants_tried``
    field and the existing escalation-ladder ``escalations`` field, so an executor that already records
    ladder ids (the recall shallow-clear fix) automatically earns variant credit here. Pure."""
    out = set()
    for key in ("variants_tried", "escalations"):
        v = entry.get(key)
        if isinstance(v, list):
            out |= {str(x).strip() for x in v if str(x).strip()}
    return out


def _depth_signals(entry: dict) -> dict:
    """Normalize an entry's recorded depth evidence into {attempts, variants, note_len, has_evidence}.
    `attempts` is the recorded count floored by the variant count (each recorded variant is at least one
    attempt); `note` is the longest of depth_note/differential; `evidence` is any non-trivial pointer."""
    variants = _variant_set(entry)
    try:
        attempts = int(entry.get("attempts") or 0)
    except (TypeError, ValueError):
        attempts = 0
    attempts = max(attempts, len(variants))
    note = ""
    for key in ("depth_note", "differential"):
        val = entry.get(key)
        if isinstance(val, str) and len(val.strip()) > len(note):
            note = val.strip()
    ev = entry.get("evidence")
    has_ev = isinstance(ev, str) and len(ev.strip()) >= 4
    return {"attempts": attempts, "variants": variants, "note_len": len(note), "has_evidence": has_ev}


def attempted_substance_gap(entry: dict, thresholds: dict):
    """Return None when an `attempted` entry is substantiated, else a short reason string naming what is
    missing. A category with >=1 finding is self-evidently substantiated. A zero-finding ('clear') attempt
    must prove depth: >= min_attempts distinct probe attempts AND >= min_variants technique variants AND a
    differential/blocker note of real length OR an evidence pointer. Pure (no I/O). A class configured to
    {min_attempts:0, min_variants:0} is depth-exempt (a deterministic, version-controlled carve-out — never
    a per-mark runtime bypass)."""
    try:
        n = int(entry.get("findings_count") or 0)
    except (TypeError, ValueError):
        n = 0
    if n >= 1:
        return None
    min_a = int(thresholds.get("min_attempts", 0) or 0)
    min_v = int(thresholds.get("min_variants", 0) or 0)
    if min_a <= 0 and min_v <= 0:
        return None
    s = _depth_signals(entry)
    missing = []
    if s["attempts"] < min_a:
        missing.append(f"attempts {s['attempts']}/{min_a}")
    if len(s["variants"]) < min_v:
        missing.append(f"variants {len(s['variants'])}/{min_v}")
    if s["note_len"] < _MIN_DEPTH_NOTE and not s["has_evidence"]:
        missing.append(f"a differential/blocker note (>={_MIN_DEPTH_NOTE} chars) or an evidence pointer")
    if not missing:
        return None
    return "zero-finding 'attempted' clear lacks depth evidence (" + "; ".join(missing) + ")"


def shallow_attempted_ids(led: dict, m: dict) -> list:
    """Category ids whose `attempted` status FAILS the depth-substance bar — a rubber-stamped shallow clear.
    The completion gate rejects these and the resume loop must re-drive them. Pure."""
    out = []
    for c in (led or {}).get("categories", []) or []:
        if not isinstance(c, dict) or str(c.get("status", "")).lower() != "attempted":
            continue
        if attempted_substance_gap(c, depth_thresholds(m, str(c.get("id") or ""))) is not None:
            out.append(str(c.get("id")))
    return out


def redrivable_ids(led: dict, m: dict) -> list:
    """Category ids the completion gate does NOT consider genuinely covered: status `pending`/`blocked`
    PLUS any shallow (depth-unsubstantiated) `attempted`. coverage.py is the single owner of what
    'genuinely covered' means, so this is the authoritative re-drivable set the resume loop re-runs
    (runloop's own pending/blocked view is a conservative subset of this). Pure, sorted."""
    out = set()
    for c in (led or {}).get("categories", []) or []:
        if isinstance(c, dict) and str(c.get("status", "")).lower() in ("pending", "blocked"):
            cid = c.get("id") or c.get("name")
            if cid:
                out.add(str(cid))
    out |= set(shallow_attempted_ids(led, m))
    return sorted(out)


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
        # FAMILY-BLOCK SUB-SURFACE GRANULARITY (QW2): a `pattern: family` category (>1 sub-agents) marked
        # `blocked` must ENUMERATE the blocked sub-surface(s) — a `blocked_subsurfaces` list, or at least a
        # reason that names a family sub-agent — or one leg's block silently absorbs an untested in-scope
        # sibling (the near-missed-P1). Recomputed from the entry's own fields (un-gameable) so a
        # hand-edited whole-family `blocked` is rejected and re-driven, not counted.
        if st == "blocked" and not _is_whole_surface_block(c):
            fam = family_agents(m, cid)
            if fam:
                named = [str(a) for a in (c.get("blocked_subsurfaces") or []) if str(a).strip()]
                reason_names = any(a.lower() in (c.get("reason") or "").lower() for a in fam)
                if not named and not reason_names:
                    errors.append(f"'{cid}' is a family (agents: {', '.join(fam)}) marked 'blocked' without "
                                  f"naming the blocked sub-surface(s) — a family block can mask an untested "
                                  f"in-scope sibling; record blocked_subsurfaces (coverage.py --mark {cid} "
                                  f"--status blocked --blocked-subsurfaces <agent/host> --note ...)")
        # DEPTH-SUBSTANCE BAR: a zero-finding `attempted` clear that does not PROVE depth is a rubber-stamp.
        # Reject it (re-computing substance from the entry's own fields, so a hand-edited status can't slip
        # through) so the gate re-routes it instead of counting a shallow pass as covered.
        if st == "attempted":
            _gap = attempted_substance_gap(c, depth_thresholds(m, cid))
            if _gap is not None:
                errors.append(f"'{cid}' is 'attempted' but {_gap} — a shallow clear is re-drivable, not covered")

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


def _merge_list(current, incoming) -> list:
    """De-duped, order-preserving merge of ``incoming`` into ``current`` (both lists of tokens)."""
    have = list(current or [])
    seen = set(have)
    for t in incoming or []:
        t = str(t).strip()
        if t and t not in seen:
            seen.add(t)
            have.append(t)
    return have


def mark(eng: Path, cat_id: str, status: str, count=None, note=None, as_json=False,
         escalations=None, attempts=None, variants=None, depth_note=None, evidence=None,
         require_depth=False, blocked_subsurfaces=None) -> int:
    """Update one ledger category in place (status / findings_count / reason / escalations + depth payload).

    This is the first-class way an orchestrator flips an entry after running a
    category, instead of hand-editing the JSON. Enforces the status enum and the
    'skipped/n/a/blocked need a reason' rule the validator checks for.

    `escalations` (a list of escalation.py ladder technique ids) is MERGED into the entry's
    `escalations` list — de-duped, order-preserving — so an executor records which ladder steps it
    climbed on an empty-but-signalled surface. The recall-audit shallow-clear gate reads this to tell an
    exhausted, honest clear from an untrustworthy first-payload clear (fix #3 — persist ladder progress).

    DEPTH-SUBSTANCE BAR (Trust: no rubber-stamped recall). `attempts` (int), `variants` (technique ids,
    merged like escalations into ``variants_tried``), `depth_note`/`differential` and `evidence` are the
    depth payload a zero-finding `attempted` clear must carry so it cannot be rubber-stamped. On an
    `attempted` flip the entry's `depth_substantiated` is (re)computed from these (a category with >=1
    finding is self-evidently substantiated). With ``require_depth`` an UNsubstantiated `attempted` flip is
    REFUSED (rc=2, nothing written) — the category then simply STAYS at its prior re-drivable status rather
    than being stamped covered. Without it the flip is still recorded but as a VISIBLY weaker
    `depth_substantiated:false` with a loud warning, and the completion gate rejects/re-drives it — so a
    shallow clear can never pass SILENTLY. Backward compatible: a mark that supplies the fields (or carries
    real findings) is unaffected.

    FAMILY-BLOCK SUB-SURFACE GRANULARITY (QW2). `blocked_subsurfaces` (a list of sub-agent ids / hosts)
    names which leg(s) of a `pattern: family` category (auth/sqli/ssrf/… — >1 sub-agents) are blocked, so
    one leg's block can't silently absorb an untested in-scope sibling. On a `blocked` flip of a family
    category the named set (this arg UNION any family sub-agent named in the reason) is recorded as
    `blocked_subsurfaces` and every un-named sibling as a still-owed `pending_subsurfaces`; a family block
    that names NOTHING is REFUSED (rc=2, nothing written). A whole-surface transport block (reason
    `"transport: ..."`) is exempt (nothing was reachable). Single-agent categories are unaffected."""
    ledger_path = eng / LEDGER_NAME
    if not ledger_path.is_file():
        print(f"[!] no {LEDGER_NAME} at {eng} (run: scripts/coverage.py --plan --engagement {eng})")
        return 2
    if status not in _MARK_STATUSES:
        print(f"[!] invalid status {status!r}; choose one of {sorted(_MARK_STATUSES)}")
        return 2
    # Lock the read-modify-write so concurrent --mark calls (one per wave subagent) can't clobber each
    # other: the load happens INSIDE the lock, after any prior writer has committed.
    with _FileLock(ledger_path):
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
        # Apply findings/reason/escalations + the depth payload to the entry FIRST, so the substance bar
        # is evaluated against the fields supplied in THIS same call (not stale on-disk state).
        if count is not None:
            hit["findings_count"] = count
        if note is not None:
            hit["reason"] = note
        if escalations:
            hit["escalations"] = _merge_list(hit.get("escalations"), escalations)
        if attempts is not None:
            try:
                hit["attempts"] = max(0, int(attempts))
            except (TypeError, ValueError):
                pass
        if variants:
            hit["variants_tried"] = _merge_list(hit.get("variants_tried"), variants)
        if depth_note is not None:
            hit["depth_note"] = depth_note
        if evidence is not None:
            hit["evidence"] = evidence

        # FAMILY-BLOCK SUB-SURFACE GRANULARITY (QW2): a `blocked` row on a `pattern: family` category
        # (auth/sqli/ssrf/xxe/… — >1 sub-agents) must NAME which sub-agent(s)/host(s) are blocked, or one
        # leg's block silently absorbs the whole family — the near-missed-P1 where `auth` blocked on its
        # out-of-scope OAuth leg masked the untested in-scope `jwt` surface. The named set is recorded as
        # `blocked_subsurfaces`; every UN-named sibling is recorded as a still-owed `pending_subsurfaces`
        # (re-drivable, NOT silently covered). Reason-named agents count too (back-compat with prose
        # reasons). A family block that names nothing is REFUSED (rc=2, nothing written) — like the
        # 'needs-a-reason' rule, the flip simply never lands and the category stays re-drivable.
        if status == "blocked" and not _is_whole_surface_block(hit):
            fam = family_agents(_safe_map(), cat_id)
            if fam:
                reason_text = (hit.get("reason") or "")
                from_reason = [a for a in fam if a.lower() in reason_text.lower()]
                named = _merge_list(from_reason, [s for s in (blocked_subsurfaces or []) if str(s).strip()])
                if not named:
                    print(f"[!] status 'blocked' on family category {cat_id!r} (agents: {', '.join(fam)}) "
                          f"must NAME which sub-agent(s)/host(s) are blocked — pass --blocked-subsurfaces "
                          f"<agent-or-host>[,...] or name them in --note. Un-named siblings stay pending so a "
                          f"family block can't silently absorb an untested in-scope sibling surface.")
                    return 2
                hit["blocked_subsurfaces"] = named
                owed = [a for a in fam if a not in named]
                if owed:
                    hit["pending_subsurfaces"] = owed
                else:
                    hit.pop("pending_subsurfaces", None)

        # DEPTH-SUBSTANCE BAR on the `attempted` flip: a zero-finding clear must PROVE depth or it is a
        # rubber-stamp. `gap` is None when substantiated (incl. any entry with >=1 finding).
        depth_gap = None
        if status == "attempted":
            depth_gap = attempted_substance_gap(hit, depth_thresholds(_safe_map(), cat_id))
            hit["depth_substantiated"] = depth_gap is None
            if depth_gap is not None and require_depth:
                # Refuse the flip: write NOTHING, so the category keeps its prior (re-drivable) status
                # instead of being stamped a shallow 'attempted' that the gate would only reject later.
                print(f"[!] refusing to mark {cat_id!r} attempted — {depth_gap}. Supply the depth payload "
                      f"(--attempts / --variants / --depth-note or --evidence) or record real findings "
                      f"(--count). The category stays re-drivable.")
                return 2
        hit["status"] = status
        atomic_write(ledger_path, json.dumps(led, indent=2) + "\n")
    if depth_gap is not None and not require_depth:
        # Non-silent: recorded, but visibly weaker (depth_substantiated:false) — the completion gate will
        # reject and re-drive this shallow clear. (Loud so it can't be rubber-stamped SILENTLY.)
        print(f"[warn] {cat_id} marked 'attempted' WITHOUT depth evidence — {depth_gap}. Recorded as "
              f"depth_substantiated:false; the completion gate will re-drive it until depth is proven "
              f"or real findings land.")
    owed_sibs = hit.get("pending_subsurfaces") or []
    if status == "blocked" and owed_sibs:
        # Loud: naming only some legs as blocked leaves the rest OWED — they are not covered by this block.
        print(f"[note] {cat_id} blocked only on {', '.join(hit.get('blocked_subsurfaces') or [])}; "
              f"sibling sub-surface(s) {', '.join(owed_sibs)} stay re-drivable (still owed, not covered).")
    if as_json:
        print(json.dumps({"id": cat_id, "status": status,
                          "findings_count": hit.get("findings_count"),
                          "reason": hit.get("reason"),
                          "escalations": hit.get("escalations", []),
                          "variants_tried": hit.get("variants_tried", []),
                          "attempts": hit.get("attempts"),
                          "blocked_subsurfaces": hit.get("blocked_subsurfaces", []),
                          "pending_subsurfaces": hit.get("pending_subsurfaces", []),
                          "depth_substantiated": hit.get("depth_substantiated")}, indent=2))
    else:
        tail = (f" findings={count}" if count is not None else "") + (f"  reason={note}" if note else "")
        tail += (f"  escalations+={len(escalations)}" if escalations else "")
        tail += (f"  variants+={len(variants)}" if variants else "")
        if status == "blocked" and hit.get("blocked_subsurfaces"):
            tail += f"  blocked_subsurfaces={','.join(hit['blocked_subsurfaces'])}"
        if status == "attempted":
            tail += f"  depth_substantiated={hit.get('depth_substantiated')}"
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
            # A finding-backed flip is self-evidently substantiated (the finding is the depth proof), so it
            # clears the depth-substance bar — record that so the completion gate never re-drives it.
            c["depth_substantiated"] = True
            changed.append(cid)
    return changed


def close_write(eng: Path, findings=None, *, source_category=None) -> list:
    """Reconcile coverage_ledger.json from the engagement's authoritative findings at CLOSE and persist it
    (atomic + locked). Best-effort: no ledger / unreadable ledger => no-op ([]). When `findings` is None,
    discovers them the way the completion gate does (root / per-skill / consolidated). Returns changed
    category ids. The reconcile is run under the ledger lock (findings discovery is done first, outside
    it, to keep the hold short) so a concurrent wave-subagent --mark can't clobber the reconciled counts."""
    ledger_path = eng / LEDGER_NAME
    if not ledger_path.is_file():
        return []
    if findings is None:
        findings = _discover_findings(eng) or []
    with _FileLock(ledger_path):
        try:
            led = json.loads(ledger_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return []
        changed = reconcile_counts(led, findings, source_category=source_category)
        if changed:
            led["generated_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            atomic_write(ledger_path, json.dumps(led, indent=2) + "\n")
    return changed


def update_ledger(eng: Path, mutate):
    """Merge-safe read-modify-write of coverage_ledger.json — the concurrent WAVE-MERGE path.

    Acquires the per-file lock, reads the CURRENT on-disk ledger (so a parallel writer's just-committed
    mark is seen, never clobbered), applies ``mutate(led)`` (edit the dict in place or return a
    replacement), refreshes ``generated_at``, then ``atomic_write``s. Returns the written ledger dict, or
    None when no ledger exists / it is unreadable. Public + ADDITIVE: the existing writers
    (``mark`` / ``close_write``) keep their signatures and are already lock-safe; the engine-core
    wave-merge step uses THIS primitive to fold a whole wave's result in atomically without a race.
    coverage.py remains the sole reconciler — this does not let another module own the ledger, it only
    gives that owner a race-free write."""
    ledger_path = Path(eng) / LEDGER_NAME
    with _FileLock(ledger_path):
        if not ledger_path.is_file():
            return None
        try:
            led = json.loads(ledger_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        out = mutate(led)
        if out is None:
            out = led
        out["generated_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        atomic_write(ledger_path, json.dumps(out, indent=2) + "\n")
        return out


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
    ap.add_argument("--attempts", type=int, help="--mark: count of distinct probe attempts run for this "
                    "category (depth-substance bar for a zero-finding 'attempted' clear)")
    ap.add_argument("--variants", help="--mark: comma-separated technique-variant id(s) actually tried; "
                    "MERGED into the entry's variants_tried (counts toward the depth-substance bar)")
    ap.add_argument("--depth-note", dest="depth_note", help="--mark: a differential/blocker note of real "
                    "length recording what the depth work observed (depth-substance bar)")
    ap.add_argument("--evidence", help="--mark: an evidence pointer for the depth work (notebook/log/path) "
                    "(satisfies the depth-substance bar's pointer requirement)")
    ap.add_argument("--require-depth", action="store_true", dest="require_depth",
                    help="--mark: REFUSE an 'attempted' flip that fails the depth-substance bar (rc=2, "
                    "nothing written) so the category stays re-drivable instead of a rubber-stamped clear")
    ap.add_argument("--blocked-subsurfaces", dest="blocked_subsurfaces",
                    help="--mark --status blocked: comma-separated sub-agent id(s)/host(s) that are blocked "
                    "on a `pattern: family` category (e.g. oauth, or auth.example.com). REQUIRED to block a "
                    "family — un-named siblings stay pending so a block can't absorb an untested sibling")
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
            with _FileLock(out / LEDGER_NAME):  # serialize the (re-)plan write vs concurrent --mark/--close
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
        var = [t.strip() for t in (args.variants or "").split(",") if t.strip()] or None
        bsub = [t.strip() for t in (args.blocked_subsurfaces or "").split(",") if t.strip()] or None
        return mark(Path(args.engagement), args.mark, args.status,
                    args.count, args.note, args.as_json, escalations=esc,
                    attempts=args.attempts, variants=var, depth_note=args.depth_note,
                    evidence=args.evidence, require_depth=args.require_depth,
                    blocked_subsurfaces=bsub)

    if args.validate:
        if not args.engagement:
            ap.error("--validate needs --engagement")
        ok, lines, msgs, = validate(Path(args.engagement), m, args.strict)
        if args.as_json:
            extra = {}
            try:
                _ledp = Path(args.engagement) / LEDGER_NAME
                if _ledp.is_file():
                    _led = json.loads(_ledp.read_text(encoding="utf-8"))
                    extra = {"redrivable": redrivable_ids(_led, m),
                             "shallow_attempted": shallow_attempted_ids(_led, m)}
            except Exception:  # noqa: BLE001
                extra = {}
            print(json.dumps({"engagement": args.engagement, "pass": ok,
                              "messages": msgs, "summary": lines, **extra}, indent=2))
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
