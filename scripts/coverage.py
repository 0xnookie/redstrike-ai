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
              For a `pattern: family` category, `--mark <family> --subsurface <agent> --status …`
              sets ONE leg's (sub-surface) status; the family's top-level status is then a derived
              ROLL-UP (worst-case / least-covered) so no family status can mask an untested leg.

  --ingest-marks  Fold EXECUTOR-EMITTED coverage into the ledger. An executor writes a STRUCTURED
              `<engagement>/<skill-name>/coverage_mark.json` (schema coverage_mark.schema.json) declaring
              the coverage it achieved; this discovers every such file, validates it, and applies each mark
              THROUGH the --mark code path — so depth-substance, sub-surface roll-up and refusal logic all
              still apply. The declarative alternative to hand-running --mark. (Needs --engagement.)

  --reaffirm  Re-affirm an already-worked category against its ALREADY-RETAINED depth payload, with NO new
              free-text note (`--reaffirm <id>` [--subsurface <leg>]). Recomputes depth_substantiated purely
              from what the entry already carries; succeeds if that substantiates the clear, REFUSES with the
              specific gap otherwise. Kills the copy-paste-note loop (re-asserting a worked class by
              re-typing the same --depth-note) that tripped the oversight/duplication classifier. (Needs
              --engagement.)

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
import contextlib
import datetime
import io
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
            except (FileExistsError, PermissionError):  # Windows: EACCES on a pending-delete .lock
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
# A sub-surface (family leg) can hold any category status EXCEPT `pipeline` (that is a capability-phase
# roll-up over findings, never a per-leg state). The task's leg-status enum: attempted|blocked|skipped|
# pending|n/a.
_SUBSURFACE_STATUSES = {"attempted", "blocked", "skipped", "pending", "n/a"}
# FAMILY ROLL-UP precedence (roadmap L-A). The family top-level `status` is a roll-up over its sub-surface
# legs: the WORST-CASE / LEAST-COVERED leg wins, so a family can never read more-covered than any one leg
# (no masking). Ordered most-concerning (dominant) -> most-covered: a single `pending` (un-run) leg keeps
# the whole family `pending` (an open gap); only when every leg is attempted/terminal does it roll up clean.
_ROLLUP_ORDER = ["pending", "blocked", "attempted", "skipped", "n/a"]

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


def rollup_status(statuses):
    """The family top-level roll-up over its sub-surface leg statuses: the worst-case / least-covered
    status present (``_ROLLUP_ORDER``: pending > blocked > attempted > skipped > n/a). None when there are
    no legs. An UNRECOGNIZED status is treated as the most concerning (ranked above pending) so a bad leg
    status can never inflate the family's coverage. Pure."""
    present = [str(s) for s in statuses if s]
    if not present:
        return None
    best = None
    for s in present:
        rank = _ROLLUP_ORDER.index(s) if s in _ROLLUP_ORDER else -1
        if best is None or rank < best[0]:
            best = (rank, s)
    return best[1]


def subsurface_map(entry: dict, fam=None) -> dict:
    """{leg_agent_id: status} for a family entry, read from the AUTHORITATIVE ``subsurfaces[]`` first, then
    filled from the #128 compat fields (``blocked_subsurfaces`` -> 'blocked', ``pending_subsurfaces`` ->
    'pending') for any leg not already covered. When ``fam`` (the routing-map agents[]) is given the result
    is restricted to those legs (a named host that is not a leg is dropped — it's not a sub-surface). {} when
    the entry carries NO per-leg detail (the uniform, backward-compatible case). Pure."""
    out = {}
    for ss in (entry.get("subsurfaces") or []):
        if not isinstance(ss, dict):
            continue
        leg = str(ss.get("agent") or ss.get("id") or "").strip()
        st = str(ss.get("status") or "").strip()
        if leg and st:
            out.setdefault(leg, st)
    for leg in (entry.get("blocked_subsurfaces") or []):
        leg = str(leg).strip()
        if leg and leg not in out:
            out[leg] = "blocked"
    for leg in (entry.get("pending_subsurfaces") or []):
        leg = str(leg).strip()
        if leg and leg not in out:
            out[leg] = "pending"
    if fam is not None:
        fam_set = set(fam)
        out = {k: v for k, v in out.items() if k in fam_set}
    return out


def _rollup_reason(roll, leg_status, fam) -> str:
    """A derived family reason that NAMES each leg group — so a rolled-up `blocked`/`skipped`/`n/a` family
    satisfies the needs-a-reason rule AND the family-block enumeration check (the blocked legs are named)."""
    buckets = [("attempted", [l for l in fam if leg_status.get(l) == "attempted"]),
               ("blocked", [l for l in fam if leg_status.get(l) == "blocked"]),
               ("pending", [l for l in fam if leg_status.get(l) == "pending"]),
               ("skipped/na", [l for l in fam if leg_status.get(l) in ("skipped", "n/a")])]
    parts = [f"{label}: {', '.join(legs)}" for label, legs in buckets if legs]
    return "family roll-up over sub-surfaces [" + "; ".join(parts) + "]"


def _apply_subsurface(hit: dict, fam: list, agent: str, status: str, reason, count):
    """Set ONE family leg's (sub-surface) status inside ``hit['subsurfaces']``, materializing every other
    routing-map leg as 'pending' the first time (so an un-marked leg is VISIBLE, never silently covered),
    then DERIVE the family roll-up: top-level ``status`` (``rollup_status``), ``reason`` (names the legs),
    ``findings_count`` (sum of the legs'), and the #128 ``blocked_subsurfaces``/``pending_subsurfaces``
    mirror so the existing gate checks keep working. Mutates ``hit`` in place. Pure w.r.t. I/O."""
    existing = {}
    order = list(fam)
    for ss in (hit.get("subsurfaces") or []):
        if not isinstance(ss, dict):
            continue
        leg = str(ss.get("agent") or ss.get("id") or "").strip()
        if not leg:
            continue
        rec = {k: v for k, v in ss.items() if k != "id"}
        rec["agent"] = leg
        existing[leg] = rec
        if leg not in order:
            order.append(leg)
    for leg in fam:
        existing.setdefault(leg, {"agent": leg, "status": "pending"})
    tgt = existing[agent]
    tgt["status"] = status
    if reason is not None:
        tgt["reason"] = reason
    if count is not None:
        tgt["findings_count"] = count
    hit["subsurfaces"] = [existing[leg] for leg in order if leg in existing]
    leg_status = {leg: str(existing[leg].get("status") or "") for leg in existing}
    roll = rollup_status(leg_status.values())
    hit["status"] = roll
    total = 0
    for ss in hit["subsurfaces"]:
        try:
            total += int(ss.get("findings_count") or 0)
        except (TypeError, ValueError):
            pass
    hit["findings_count"] = total
    blocked_legs = [leg for leg in fam if leg_status.get(leg) == "blocked"]
    pending_legs = [leg for leg in fam if leg_status.get(leg) == "pending"]
    if blocked_legs:
        hit["blocked_subsurfaces"] = blocked_legs
    else:
        hit.pop("blocked_subsurfaces", None)
    if pending_legs:
        hit["pending_subsurfaces"] = pending_legs
    else:
        hit.pop("pending_subsurfaces", None)
    hit["reason"] = _rollup_reason(roll, leg_status, fam)
    if roll == "attempted":
        hit["depth_substantiated"] = attempted_substance_gap(
            hit, depth_thresholds(_safe_map(), str(hit.get("id") or ""))) is None
    return roll


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


def _load_vc():
    """Lazy-load the _contract/verify_completion module BY PATH (scripts/ may not be a package on the path).
    Shared by the findings-discovery cross-check and the coverage-mark schema validation — both reuse this
    one loader. Returns the module, or None if it can't be loaded (callers then degrade gracefully)."""
    global _VC_MOD
    if _VC_MOD is None:
        try:
            import importlib.util
            p = ROOT / "skills" / "_contract" / "verify_completion.py"
            spec = importlib.util.spec_from_file_location("rs_vc_coverage", p)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            _VC_MOD = mod
        except Exception:  # noqa: BLE001
            _VC_MOD = None
    return _VC_MOD


def _discover_findings(eng: Path):
    """Reuse verify_completion's multi-layout finding discovery (root / per-skill / consolidated) so the
    soft cross-check fires on the REAL per-skill layout (<eng>/*/findings.json), not only a root
    findings.json. Returns a flat list, or None when none/unparseable (cross-check then skipped)."""
    vc = _load_vc()
    if vc is None:
        return None
    try:
        findings, _src = vc._discover_engagement_findings(eng)
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
                # a subsurfaces[] leg recorded 'blocked' is an enumeration too (the authoritative form).
                sub_blocked = [k for k, v in subsurface_map(c, fam).items() if v == "blocked"]
                reason_names = any(a.lower() in (c.get("reason") or "").lower() for a in fam)
                if not named and not sub_blocked and not reason_names:
                    errors.append(f"'{cid}' is a family (agents: {', '.join(fam)}) marked 'blocked' without "
                                  f"naming the blocked sub-surface(s) — a family block can mask an untested "
                                  f"in-scope sibling; record blocked_subsurfaces (coverage.py --mark {cid} "
                                  f"--status blocked --blocked-subsurfaces <agent/host> --note ...)")
        # SUB-SURFACE / PER-LEG ACCOUNTING (roadmap L-A): generalize the blocked-only rule above to ALL
        # statuses. Once a family records ANY per-leg detail (subsurfaces[] / blocked_/pending_subsurfaces)
        # it must account for EVERY routing-map leg (an un-named leg can hide a silent untested surface), and
        # a family claiming `attempted` must not carry a leg that is still pending/blocked — an `attempted`
        # family with an untested leg is a GAP, not a silent pass (the near-missed-P1 root cause). A family
        # with NO per-leg detail is the uniform, backward-compatible case (handled exactly as before).
        # Recomputed from the entry's own fields so a hand-edited roll-up can't slip through.
        if st not in ("pipeline",) and not _is_whole_surface_block(c):
            fam2 = family_agents(m, cid)
            leg_map = subsurface_map(c, fam2) if fam2 else {}
            if fam2 and leg_map:
                unaccounted = [a for a in fam2 if a not in leg_map]
                if unaccounted:
                    errors.append(f"'{cid}' is a family (agents: {', '.join(fam2)}) that records sub-surface "
                                  f"status for some legs but NOT {', '.join(unaccounted)} — an un-accounted leg "
                                  f"can hide an untested surface; mark it (coverage.py --mark {cid} "
                                  f"--subsurface <agent> --status ...)")
                if st == "attempted":
                    uncovered = [a for a in fam2 if leg_map.get(a) in ("pending", "blocked")]
                    if uncovered:
                        errors.append(f"'{cid}' is 'attempted' but sub-surface leg(s) {', '.join(uncovered)} "
                                      f"are not covered (pending/blocked) — a family 'attempted' must not mask "
                                      f"an untested/under-covered leg; mark each leg (coverage.py --mark {cid} "
                                      f"--subsurface <agent> --status ...) or roll the family down")
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
    # SUB-SURFACE / PER-LEG ROLL-UP (roadmap L-A): the family top-level status is the worst-case / least-
    # covered leg — a single un-run leg keeps the family open, so no family status masks an untested leg.
    assert rollup_status(["attempted", "attempted", "attempted"]) == "attempted"
    assert rollup_status(["attempted", "pending", "attempted"]) == "pending"   # one un-run leg dominates
    assert rollup_status(["attempted", "skipped", "n/a"]) == "attempted"
    assert rollup_status(["blocked", "attempted"]) == "blocked"
    assert rollup_status([]) is None
    _fam = family_agents(m, "auth")                       # ["auth-bypass", "jwt", "oauth"]
    _e = {"id": "auth", "status": "pending"}
    _apply_subsurface(_e, _fam, "jwt", "attempted", "jwt forge battery ran, all rejected", 0)
    assert _e["status"] == "pending", _e                  # auth-bypass + oauth still pending -> family pending
    assert {s["agent"]: s["status"] for s in _e["subsurfaces"]}["jwt"] == "attempted"
    assert sorted(_e["pending_subsurfaces"]) == ["auth-bypass", "oauth"]
    for _leg in _fam:                                      # cover every leg -> family rolls up attempted
        _apply_subsurface(_e, _fam, _leg, "attempted", "ran", 0)
    assert _e["status"] == "attempted" and not _e.get("pending_subsurfaces"), _e
    # EXECUTOR-EMITTED COVERAGE MARKS (roadmap L-G): a coverage_mark.json folds in through mark(), and
    # --reaffirm re-asserts a worked class from its retained payload with no new note.
    import tempfile
    with tempfile.TemporaryDirectory() as _d:
        _eng = Path(_d)
        _led = plan(m, None, {"web"}, _eng.name)
        atomic_write(_eng / LEDGER_NAME, json.dumps(_led, indent=2) + "\n")
        (_eng / "sqli").mkdir()
        atomic_write(_eng / "sqli" / MARK_NAME, json.dumps(
            {"category": "sqli", "status": "attempted", "findings_count": 0, "attempts": 6,
             "variants": ["derive-not-assume", "encoding-ladder"],
             "depth_note": "boolean/time/union differential all negative on id,q,search"}) + "\n")
        with contextlib.redirect_stdout(io.StringIO()):
            _rc = ingest_marks(_eng, require_depth=True)
        assert _rc == 0, "a substantiated executor mark must ingest clean"
        _back = json.loads((_eng / LEDGER_NAME).read_text(encoding="utf-8"))
        _sqli = next(c for c in _back["categories"] if c["id"] == "sqli")
        assert _sqli["status"] == "attempted" and _sqli["depth_substantiated"] is True, _sqli
        assert _sqli["variants_tried"] == ["derive-not-assume", "encoding-ladder"], _sqli
        # --reaffirm against the now-retained payload succeeds with NO new note.
        with contextlib.redirect_stdout(io.StringIO()):
            assert reaffirm(_eng, "sqli") == 0
        # a bare clear with no retained depth (cors is pending, zero payload) is REFUSED by --reaffirm
        # (it never invents a note).
        with contextlib.redirect_stdout(io.StringIO()):
            assert reaffirm(_eng, "cors") == 2, "an un-substantiated clear cannot be reaffirmed"
    print("coverage.py selftest: OK "
          f"({len(ids)} categories, {len(set(agents))} executors, orphans wired, phases auto-activate, "
          f"executor-marks ingest + reaffirm)")
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
         require_depth=False, blocked_subsurfaces=None, subsurface=None) -> int:
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

    SUB-SURFACE / PER-LEG GRANULARITY (roadmap L-A). `subsurface` (a family sub-agent / leg id) sets THAT
    leg's status (``status`` is then the LEG status: attempted|blocked|skipped|pending|n/a) in the entry's
    authoritative ``subsurfaces[]`` list, materializing every other routing-map leg as 'pending' the first
    time, and DERIVES the family top-level status as a worst-case / least-covered ROLL-UP — so no family
    status can mask an untested leg. Any depth payload (--attempts/--variants/--depth-note/--evidence) passed
    with it applies at the family level (for the roll-up's depth-substance check). Only valid on a
    `pattern: family` category; single-agent categories reject it.

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
        # SUB-SURFACE / PER-LEG MARK (roadmap L-A): `--subsurface <agent> --status <leg-status>` sets ONE
        # family leg's status and derives the family roll-up. A separate, self-contained path (returns from
        # inside the lock, releasing it): the family top-level status/reason/findings_count become a DERIVED
        # roll-up, never hand-set, so the family can't read more-covered than its least-covered leg.
        if subsurface:
            fam = family_agents(_safe_map(), cat_id)
            if not fam:
                print(f"[!] --subsurface is only valid on a `pattern: family` category (>1 sub-agents); "
                      f"{cat_id!r} is not one")
                return 2
            if subsurface not in fam:
                print(f"[!] {subsurface!r} is not a sub-agent of family {cat_id!r} (legs: {', '.join(fam)})")
                return 2
            if status not in _SUBSURFACE_STATUSES:
                print(f"[!] sub-surface status {status!r} invalid; choose one of "
                      f"{sorted(_SUBSURFACE_STATUSES)}")
                return 2
            if status in _NEED_REASON and not (note or "").strip():
                print(f"[!] sub-surface status {status!r} on leg {subsurface!r} requires a reason — "
                      f"pass --note \"...\"")
                return 2
            # family-level depth payload supplied alongside the leg mark (used by the roll-up's depth check)
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
            roll = _apply_subsurface(hit, fam, subsurface, status, note, count)
            atomic_write(ledger_path, json.dumps(led, indent=2) + "\n")
            owed = hit.get("pending_subsurfaces") or []
            if as_json:
                print(json.dumps({"id": cat_id, "subsurface": subsurface, "subsurface_status": status,
                                  "status": roll, "findings_count": hit.get("findings_count"),
                                  "subsurfaces": hit.get("subsurfaces", []),
                                  "pending_subsurfaces": owed,
                                  "blocked_subsurfaces": hit.get("blocked_subsurfaces", []),
                                  "depth_substantiated": hit.get("depth_substantiated")}, indent=2))
            else:
                tail = f"  owed={','.join(owed)}" if owed else ""
                print(f"ok: {cat_id} subsurface {subsurface} -> {status}; family roll-up -> {roll}{tail}")
            return 0
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


# --- EXECUTOR-EMITTED COVERAGE MARKS (roadmap L-G) ------------------------------------------------- #
# Today the orchestrator marks coverage by hand-running `coverage.py --mark <cat> --status attempted
# --depth-note "..." --evidence ...`. Two problems the retro flagged: an executor can't emit its OWN
# coverage declaratively, and re-affirming an already-worked category forced copy-pasting the same
# free-text depth note (which tripped an oversight/duplication classifier). This block adds:
#   * a STRUCTURED, executor-emitted artifact `<engagement>/<skill-name>/coverage_mark.json` (schema
#     coverage_mark.schema.json) that `--ingest-marks` folds into the ledger THROUGH the existing mark()
#     path — so every depth-substance, sub-surface roll-up and refusal rule still applies, nothing is
#     bypassed; and
#   * a `--reaffirm <CATEGORY>` op that re-affirms a category against its ALREADY-RETAINED depth payload
#     with NO new free-text note, killing the copy-paste-note loop.
MARK_NAME = "coverage_mark.json"
MARK_SCHEMA_REL = "skills/_contract/coverage_mark.schema.json"


def _validate_mark_doc(data):
    """Validate a loaded coverage_mark.json document (a single mark object OR an array of them) against
    coverage_mark.schema.json, REUSING verify_completion's schema validator (the `jsonschema` package when
    present, else the repo's stdlib subset checker) — the same approach the artifact gate uses. Returns
    (ok, note). DEGRADES GRACEFULLY: if the validator module can't be loaded at all, returns
    (True, "...unavailable") so ingest still proceeds — mark() re-enforces status/reason/depth itself, so a
    malformed mark can't slip through even when schema pre-validation is skipped."""
    vc = _load_vc()
    if vc is None or not hasattr(vc, "_validate_against_schema"):
        return True, "schema check unavailable (validator not importable)"
    try:
        return vc._validate_against_schema(data, MARK_SCHEMA_REL)
    except Exception as e:  # noqa: BLE001
        return True, f"schema check error: {e} (skipped)"


def _apply_mark_obj(eng: Path, obj: dict, require_depth: bool = True):
    """Apply ONE validated mark object THROUGH the existing mark() code path (so depth-substance, family
    roll-up and refusal logic are never bypassed), capturing mark()'s message. Returns (rc, detail):
    rc==0 => applied, rc!=0 => refused by mark()'s own rules (under-depth, missing reason, un-named family
    block, unknown category/leg). Pure field mapping from the artifact vocabulary onto mark()'s signature."""
    cat = str(obj.get("category") or "").strip()
    status = str(obj.get("status") or "").strip()
    count = obj.get("findings_count")
    if isinstance(count, bool):            # JSON true/false is never a count
        count = None
    attempts = obj.get("attempts")
    if isinstance(attempts, bool):
        attempts = None
    variants = [str(v).strip() for v in (obj.get("variants") or []) if str(v).strip()] or None
    escalations = [str(v).strip() for v in (obj.get("escalations") or []) if str(v).strip()] or None
    blocked_sub = [str(v).strip() for v in (obj.get("blocked_subsurfaces") or []) if str(v).strip()] or None
    note = obj.get("reason")
    depth_note = obj.get("depth_note")
    if depth_note is None:                 # `differential` is the documented alias for depth_note
        depth_note = obj.get("differential")
    evidence = obj.get("evidence")
    subsurface = obj.get("subsurface") or None
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = mark(eng, cat, status, count=count, note=note, as_json=False,
                  escalations=escalations, attempts=attempts, variants=variants,
                  depth_note=depth_note, evidence=evidence, require_depth=require_depth,
                  blocked_subsurfaces=blocked_sub, subsurface=subsurface)
    return rc, buf.getvalue().strip()


def ingest_marks(eng: Path, as_json: bool = False, require_depth: bool = True) -> int:
    """Discover every `<eng>/*/coverage_mark.json`, validate each against coverage_mark.schema.json, and fold
    each mark into coverage_ledger.json THROUGH the existing mark() path (so all depth-substance, sub-surface
    roll-up and refusal logic still applies — nothing is bypassed). Idempotent + concurrency-safe: each
    mark() call takes the ledger lock on its own (ingest never holds an outer lock, so a wave subagent's
    concurrent --mark can't deadlock against it). A successfully-ingested mark FILE is LEFT IN PLACE and
    logged — engagement artifacts are never silently deleted, and leaving the file keeps ingest idempotent
    (re-applying the same mark is a no-op in effect). Returns 0 only when every discovered mark applied
    cleanly; 2 when a mark file was malformed/schema-invalid or any individual mark was REFUSED (the per-mark
    report says which, so the orchestrator knows what stays re-drivable)."""
    eng = Path(eng)
    ledger_path = eng / LEDGER_NAME
    if not ledger_path.is_file():
        msg = f"[!] no {LEDGER_NAME} at {eng} (run: scripts/coverage.py --plan --engagement {eng})"
        print(json.dumps({"engagement": str(eng), "error": msg}, indent=2) if as_json else msg)
        return 2
    files = sorted(eng.glob("*/" + MARK_NAME))
    results = []
    rc_overall = 0
    for mf in files:
        rel = mf.relative_to(eng).as_posix()
        try:
            data = json.loads(mf.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            results.append({"file": rel, "ok": False, "applied": False,
                            "detail": f"unreadable / invalid JSON: {e}"})
            rc_overall = 2
            continue
        ok_schema, note = _validate_mark_doc(data)
        if not ok_schema:
            results.append({"file": rel, "ok": False, "applied": False, "detail": f"schema: {note}"})
            rc_overall = 2
            continue
        objs = data if isinstance(data, list) else [data]
        for idx, obj in enumerate(objs):
            if not isinstance(obj, dict):
                results.append({"file": rel, "index": idx, "ok": False, "applied": False,
                                "detail": "mark is not an object"})
                rc_overall = 2
                continue
            rc, detail = _apply_mark_obj(eng, obj, require_depth)
            applied = rc == 0
            results.append({"file": rel, "index": idx, "category": obj.get("category"),
                            "subsurface": obj.get("subsurface"), "status": obj.get("status"),
                            "ok": True, "applied": applied, "detail": detail})
            if not applied:
                rc_overall = 2
    if as_json:
        print(json.dumps({"engagement": str(eng), "mark_files": len(files),
                          "results": results, "pass": rc_overall == 0}, indent=2))
    else:
        if not files:
            print(f"ingest-marks: no {MARK_NAME} files under {eng} (nothing to ingest)")
        else:
            n_applied = sum(1 for r in results if r.get("applied"))
            n_refused = sum(1 for r in results if r.get("ok") and not r.get("applied"))
            n_bad = sum(1 for r in results if not r.get("ok"))
            print(f"ingest-marks: {len(files)} file(s); {n_applied} applied, "
                  f"{n_refused} refused, {n_bad} invalid")
            for r in results:
                tag = "applied" if r.get("applied") else ("INVALID" if not r.get("ok") else "REFUSED")
                where = r["file"] + (f"[{r['index']}]" if "index" in r else "")
                cat = r.get("category") or ""
                leg = f"/{r['subsurface']}" if r.get("subsurface") else ""
                st = r.get("status") or ""
                detail = ("  — " + r["detail"]) if r.get("detail") else ""
                print(f"  [{tag:^8}] {where}: {cat}{leg} -> {st}{detail}")
            print("\nNote: ingested mark files are left in place (engagement artifacts are never deleted).")
    return rc_overall


def _entry_substance_gap(hit: dict, m: dict):
    """The depth-substance gap of a ledger entry computed PURELY from its already-retained fields (attempts +
    variants_tried/escalations + an existing depth_note/differential/evidence, or >=1 finding) — no new
    input. None => the retained payload substantiates an `attempted` clear."""
    return attempted_substance_gap(hit, depth_thresholds(m, str(hit.get("id") or "")))


def reaffirm(eng: Path, cat_id: str, subsurface=None, as_json: bool = False) -> int:
    """Re-affirm an already-worked category against its ALREADY-RETAINED depth payload, with NO new free-text
    note — the replacement for the copy-paste-note loop (re-running `--mark <cat> --status attempted
    --depth-note "<the same note again>"` to re-assert a worked category tripped an oversight/duplication
    classifier). Recomputes depth_substantiated PURELY from the entry's retained fields: if the retained
    payload SUBSTANTIATES the clear, sets status=attempted (refreshing the ledger timestamp) and succeeds; if
    it is absent or insufficient, REFUSES (rc=2) naming the specific gap — it never invents a note. Supports
    --subsurface to re-affirm ONE family leg from its retained state, re-deriving the family roll-up.
    Concurrency-safe (own read-modify-write under the ledger lock)."""
    ledger_path = eng / LEDGER_NAME
    if not ledger_path.is_file():
        print(f"[!] no {LEDGER_NAME} at {eng} (run: scripts/coverage.py --plan --engagement {eng})")
        return 2
    m = _safe_map()
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
        fam = family_agents(m, cat_id)
        # --- sub-surface (family leg) reaffirm --------------------------------------------------------
        if subsurface:
            if not fam:
                print(f"[!] --subsurface is only valid on a `pattern: family` category (>1 sub-agents); "
                      f"{cat_id!r} is not one")
                return 2
            if subsurface not in fam:
                print(f"[!] {subsurface!r} is not a sub-agent of family {cat_id!r} (legs: {', '.join(fam)})")
                return 2
            legmap = subsurface_map(hit, fam)
            cur = legmap.get(subsurface)
            if cur is None:
                print(f"[!] refusing to reaffirm leg {subsurface!r} of {cat_id!r} — it has no retained "
                      f"status to reaffirm (mark the leg first).")
                return 2
            existing = next((s for s in (hit.get("subsurfaces") or [])
                             if str(s.get("agent") or s.get("id") or "").strip() == subsurface), {})
            roll = _apply_subsurface(hit, fam, subsurface, cur,
                                     existing.get("reason"), existing.get("findings_count"))
            led["generated_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            atomic_write(ledger_path, json.dumps(led, indent=2) + "\n")
            if as_json:
                print(json.dumps({"id": cat_id, "subsurface": subsurface, "subsurface_status": cur,
                                  "status": roll, "reaffirmed": True}, indent=2))
            else:
                print(f"ok: reaffirmed {cat_id} leg {subsurface} -> {cur}; family roll-up -> {roll}")
            return 0
        # --- category-level reaffirm ------------------------------------------------------------------
        # A family that records per-leg detail must NOT be reaffirmed while a leg is still uncovered — that
        # would mask an untested leg (the sub-surface rule). Refuse and name the uncovered legs.
        if fam:
            legmap = subsurface_map(hit, fam)
            uncovered = [a for a in fam if legmap.get(a) in ("pending", "blocked")]
            if legmap and uncovered:
                print(f"[!] refusing to reaffirm {cat_id!r} — family leg(s) {', '.join(uncovered)} are not "
                      f"covered (pending/blocked); reaffirm/mark those legs first. A family can't be "
                      f"reaffirmed over an untested leg.")
                return 2
        gap = _entry_substance_gap(hit, m)
        if gap is not None:
            print(f"[!] refusing to reaffirm {cat_id!r} — the retained depth payload does not substantiate "
                  f"the clear: {gap}. Re-run the class with the depth payload (--attempts / --variants / "
                  f"--depth-note or --evidence) or record findings; reaffirm will not invent a note. The "
                  f"category stays re-drivable.")
            return 2
        hit["status"] = "attempted"
        hit["depth_substantiated"] = True
        led["generated_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        atomic_write(ledger_path, json.dumps(led, indent=2) + "\n")
    if as_json:
        print(json.dumps({"id": cat_id, "status": "attempted", "depth_substantiated": True,
                          "reaffirmed": True, "findings_count": hit.get("findings_count")}, indent=2))
    else:
        print(f"ok: reaffirmed {cat_id} -> attempted (depth_substantiated from the retained payload; "
              f"no new note)")
    return 0


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
    ap.add_argument("--subsurface", dest="subsurface",
                    help="--mark: set ONE sub-surface (family leg / sub-agent) status on a `pattern: family` "
                    "category — `--mark <family> --subsurface <agent> --status <attempted|blocked|skipped|"
                    "pending|n/a>`. The family's top-level status becomes a derived worst-case roll-up so no "
                    "family status can mask an untested leg")
    ap.add_argument("--ingest-marks", action="store_true", dest="ingest_marks",
                    help="discover every <eng>/*/coverage_mark.json, validate each against "
                         "coverage_mark.schema.json, and fold it into the ledger THROUGH the --mark path "
                         "(the declarative, executor-emitted coverage path; needs --engagement)")
    ap.add_argument("--reaffirm", metavar="CATEGORY_ID",
                    help="re-affirm a category from its ALREADY-RETAINED depth payload with NO new note "
                         "(needs --engagement) — replaces the copy-paste-note loop. Add --subsurface for a "
                         "family leg. Refuses if the retained payload doesn't substantiate the clear")
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

    if args.ingest_marks:
        if not args.engagement:
            ap.error("--ingest-marks needs --engagement")
        return ingest_marks(Path(args.engagement), args.as_json)

    if args.reaffirm:
        if not args.engagement:
            ap.error("--reaffirm needs --engagement")
        return reaffirm(Path(args.engagement), args.reaffirm,
                        subsurface=args.subsurface, as_json=args.as_json)

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
                    blocked_subsurfaces=bsub, subsurface=args.subsurface)

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

    ap.error("choose one of --plan / --validate / --mark / --ingest-marks / --reaffirm / --close / "
             "--list / --selftest")


if __name__ == "__main__":
    sys.exit(main())
