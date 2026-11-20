"""Per-engagement run diagnostics — reliability/observability, NOT offense.

An engagement can "finish and do nothing": the engine exits clean, the report is empty, and
nothing says WHY. Empty recon is indistinguishable from a genuinely clean target, and the block
tally the rate gate keeps in ``runtime/rate_state.json`` is write-only — nobody reads it back. This
module closes that gap. After the post-run gate it classifies each launch into one of four
outcomes and records a per-engagement artifact (``runtime/diagnostics.json``, a ``runs[]`` array
appended per launch) plus an append-only human ``runtime/error.log``:

    produced-findings  accepted findings exist — we delivered.
    clean-tested       zero findings, but the surface WAS tested and the transport was healthy.
    degraded-empty     zero findings for a concrete reliability reason (recon found nothing /
                       every class was skipped / tools failed / the transport was blocked /
                       the run hit its cap) — empty does NOT mean clean.
    failed             the engine crashed / returned a non-zero rc and did not complete.

SCOPE / HONESTY
  * This is observability about OURSELVES — "we were blocked / we skipped / we crashed". It never
    authors or stores WAF-bypass or evasion material. ``transport_health`` is IDENTITY
    FINGERPRINTING (which WAF/CDN, by its own advertised headers/cookies) + block-rate RECORDING
    only. It exists so an operator can tell "unreliable coverage behind a WAF" from "clean target".
  * The transport numbers are a FLOOR: the rate gate parses statuses best-effort from free-form
    tool output, so a real block the parser missed simply isn't counted. A low block rate is
    therefore never proof of a healthy transport — only a high one is proof of an unhealthy one.

The pure pieces (``classify_outcome``, ``transport_rollup``, the small extractors) take parsed
data and are unit-tested directly; ``assemble`` is the thin glue that reads the engagement's files
and ``write`` persists the record. Secrets in the human log are redacted via ``audit.redact_text``.
"""
from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass, field
from pathlib import Path

from . import audit as auditmod

# --- schema version ----------------------------------------------------------
# Bumped to 2 when the optional per-run ``tooling_health`` block was added (toolchain preflight →
# runtime/tooling.json). Written into the diagnostics document as the drift guard the schema reserves.
DIAG_SCHEMA_VERSION = 2

# --- outcomes ----------------------------------------------------------------
PRODUCED = "produced-findings"
CLEAN = "clean-tested"
DEGRADED = "degraded-empty"
FAILED = "failed"

# --- thresholds --------------------------------------------------------------
# A host (or the engagement overall) counts as "blocked" at or above this share of requests
# blocked/challenged — the point past which empty findings can no longer be trusted as "clean".
HIGH_BLOCK_RATE = 0.5
# Finding statuses that count as a real, delivered finding (mirrors gate.status's "accepted").
ACCEPTED_STATUSES = frozenset({"verified", "accepted", "remediated"})


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


# --- the record --------------------------------------------------------------
@dataclass
class Diagnostics:
    """One run record. ``to_record()`` renders the pinned ``runs[]`` entry shape verbatim."""
    session: str = ""
    mode: str = "interactive"
    started: str = ""
    ended: str = ""
    engine_rc: int = 0
    gate_rc: int | None = None
    outcome: str = DEGRADED
    degraded_reason: str | None = None
    findings_count: int = 0
    tool_failures: list = field(default_factory=list)
    exceptions: list = field(default_factory=list)
    transport_health: dict = field(default_factory=lambda: {"hosts": [], "overall": {
        "block_rate": 0.0, "worst_host": None, "status": "healthy"}})
    empty_recon: dict = field(default_factory=lambda: {
        "flag": False, "surface_discovered": 0, "signals": 0, "hosts_live": 0})
    phase_tally: list = field(default_factory=list)
    gate_summary: dict = field(default_factory=lambda: {
        "coverage": "absent", "surface": "absent", "recall": "n/a", "findings": 0})
    # OPTIONAL (schema v2): the toolchain-health rollup for this run, or None when no snapshot was
    # taken (e.g. an interactive close). Kept OPTIONAL so a minimal record still validates and so the
    # existing pinned field set is unchanged when absent — it is emitted ONLY when present.
    tooling_health: dict | None = None

    def to_record(self) -> dict:
        """The exact pinned ``runs[]`` entry (ordered, closed shape Phase 2 consumes). ``tooling_health``
        is appended ONLY when present, so a run with no tooling snapshot renders the original field set
        verbatim (backward-compatible)."""
        rec = {
            "session": self.session,
            "mode": self.mode,
            "started": self.started,
            "ended": self.ended,
            "engine_rc": int(self.engine_rc),
            "gate_rc": (None if self.gate_rc is None else int(self.gate_rc)),
            "outcome": self.outcome,
            "degraded_reason": self.degraded_reason,
            "findings_count": int(self.findings_count),
            "tool_failures": list(self.tool_failures),
            "exceptions": list(self.exceptions),
            "transport_health": self.transport_health,
            "empty_recon": self.empty_recon,
            "phase_tally": list(self.phase_tally),
            "gate_summary": self.gate_summary,
        }
        if self.tooling_health is not None:
            rec["tooling_health"] = self.tooling_health
        return rec


# --- transport rollup (pure) -------------------------------------------------
def _host_classification(req: int, blocks: int, challenges: int, rate: float) -> str:
    if req <= 0:
        return "healthy"
    if rate >= HIGH_BLOCK_RATE:
        return "blocked"
    if blocks > 0 or challenges > 0:
        return "degraded"
    return "healthy"


def transport_rollup(rate_state: dict) -> dict:
    """Build ``transport_health`` from the per-host tally in ``runtime/rate_state.json``.

    Reads only what the rate gate already recorded (requests/blocks/status histogram/challenge
    count/WAF identity/timestamps). Computes a per-host block_rate + classification and an overall
    rollup whose status is the worst host's classification. ``worst_host`` is the host with the
    highest block_rate (ties broken by request volume), or None when nothing was ever blocked.
    """
    hosts_in = (rate_state or {}).get("hosts") or {}
    hosts_out: list[dict] = []
    tot_req = tot_blk = 0
    for host, hs in sorted(hosts_in.items()):
        hs = hs or {}
        req = int(hs.get("total_requests", 0) or 0)
        blk = int(hs.get("total_blocks", 0) or 0)
        ch = int(hs.get("challenges", 0) or 0)
        statuses = {str(k): int(v) for k, v in (hs.get("statuses") or {}).items()}
        rate = (blk / req) if req > 0 else 0.0
        hosts_out.append({
            "host": host,
            "requests": req,
            "blocks": blk,
            "block_rate": round(rate, 4),
            "statuses": statuses,
            "challenges": ch,
            "waf": hs.get("waf") or None,
            "classification": _host_classification(req, blk, ch, rate),
            "first_block_ts": hs.get("first_block_ts") or None,
            "last_ok_ts": hs.get("last_ok_ts") or None,
        })
        tot_req += req
        tot_blk += blk
    overall_rate = (tot_blk / tot_req) if tot_req > 0 else 0.0
    # worst host: highest block_rate, then most requests; only if it actually saw a block.
    worst_host = None
    if hosts_out:
        cand = sorted(hosts_out, key=lambda h: (h["block_rate"], h["requests"]), reverse=True)[0]
        if cand["blocks"] > 0:
            worst_host = cand["host"]
    if any(h["classification"] == "blocked" for h in hosts_out):
        status = "blocked"
    elif any(h["classification"] == "degraded" for h in hosts_out):
        status = "degraded"
    else:
        status = "healthy"
    return {
        "hosts": hosts_out,
        "overall": {"block_rate": round(overall_rate, 4), "worst_host": worst_host, "status": status},
    }


def _worst_host_waf(transport_health: dict, worst_host: str | None) -> str | None:
    for h in (transport_health or {}).get("hosts") or []:
        if h.get("host") == worst_host:
            return h.get("waf") or None
    return None


# --- tooling rollup (pure) ---------------------------------------------------
def tooling_rollup(tooling: dict | None) -> dict | None:
    """Build the record's optional ``tooling_health`` block from a parsed ``runtime/tooling.json``
    snapshot (as written by ``preflight.tooling_snapshot``). Normalizes each capability to
    ``{capability, primary, present, fallback, status}`` and recomputes ``overall`` from the parsed
    data (never trusts the file's own count).

    Returns None when there is no usable snapshot, so a run with no tooling probe omits the field
    entirely (schema-optional → the original run-record shape is preserved, backward-compatible)."""
    if not isinstance(tooling, dict):
        return None
    caps_in = tooling.get("capabilities")
    if not isinstance(caps_in, list) or not caps_in:
        return None
    caps: list[dict] = []
    degraded = 0
    for c in caps_in:
        if not isinstance(c, dict):
            continue
        status = str(c.get("status", "")).lower()
        if status not in ("ok", "degraded"):
            status = "ok" if c.get("present") else "degraded"
        if status == "degraded":
            degraded += 1
        fb = c.get("fallback")
        caps.append({
            "capability": str(c.get("capability", "?")),
            "primary": str(c.get("primary", "")),
            "present": bool(c.get("present", False)),
            "fallback": fb if isinstance(fb, str) and fb else None,
            "status": status,
        })
    if not caps:
        return None
    probed = tooling.get("generated_at")
    return {
        "capabilities": caps,
        "overall": {"degraded_count": degraded, "status": "degraded" if degraded else "ok"},
        "probed_at": probed if isinstance(probed, str) and probed else None,
    }


def _degraded_capabilities(tooling_health: dict | None) -> list[dict]:
    if not isinstance(tooling_health, dict):
        return []
    return [c for c in (tooling_health.get("capabilities") or [])
            if isinstance(c, dict) and str(c.get("status", "")).lower() == "degraded"]


# --- coverage/surface extractors (pure) --------------------------------------
def _coverage_counts(coverage_ledger: dict | None) -> dict:
    out = {"attempted": 0, "skipped": 0, "pending": 0, "blocked": 0, "na": 0, "total": 0}
    if not isinstance(coverage_ledger, dict):
        return out
    for c in coverage_ledger.get("categories") or []:
        if not isinstance(c, dict):
            continue
        st = str(c.get("status", "")).lower()
        out["total"] += 1
        if st == "attempted":
            out["attempted"] += 1
        elif st == "skipped":
            out["skipped"] += 1
        elif st == "pending":
            out["pending"] += 1
        elif st == "blocked":
            out["blocked"] += 1
        elif st in ("n/a", "na"):
            out["na"] += 1
    return out


def _surface_total(surface_ledger: dict | None) -> int:
    if not isinstance(surface_ledger, dict):
        return 0
    return len(surface_ledger.get("surfaces") or [])


def _surface_tested_count(surface_ledger: dict | None) -> int:
    if not isinstance(surface_ledger, dict):
        return 0
    return sum(1 for s in (surface_ledger.get("surfaces") or [])
               if isinstance(s, dict) and str(s.get("status", "")).lower() == "tested")


def _surface_discovered_untested(surface_ledger: dict | None) -> int:
    if not isinstance(surface_ledger, dict):
        return 0
    return sum(1 for s in (surface_ledger.get("surfaces") or [])
               if isinstance(s, dict) and str(s.get("status", "")).lower() == "discovered")


def _was_tested(coverage_ledger: dict | None, surface_ledger: dict | None) -> bool:
    """Positive evidence that SOMETHING was actually tested — a category ran, or a surface element
    was consumed. 'clean-tested' requires this; without it, zero findings is indeterminate."""
    return (_coverage_counts(coverage_ledger)["attempted"] > 0
            or _surface_tested_count(surface_ledger) > 0)


# --- outcome classification (pure) -------------------------------------------
def _recon_is_empty(empty_recon: dict | None, surface_ledger: dict | None) -> bool:
    """True when recon came up with ~0 live hosts AND ~0 attack surface. Prefers the already-computed
    ``empty_recon`` extract (hosts_live + surface_discovered); falls back to the surface ledger total
    when no extract was passed."""
    if isinstance(empty_recon, dict):
        return (int(empty_recon.get("hosts_live", 0) or 0) == 0
                and int(empty_recon.get("surface_discovered", 0) or 0) == 0)
    if surface_ledger is not None:
        return _surface_total(surface_ledger) == 0
    return False


def classify_outcome(summary: dict, coverage_ledger: dict | None,
                     surface_ledger: dict | None, transport_health: dict,
                     tooling_health: dict | None = None,
                     empty_recon: dict | None = None) -> tuple[str, str | None]:
    """Classify a run into one of the four outcomes + a concrete ``degraded_reason`` (None for the
    healthy outcomes).

    ``summary`` is a plain dict with: ``findings_count`` (accepted findings), ``engine_rc``,
    ``tool_failures`` (list), ``exceptions`` (list), ``cap_hit`` (bool), ``stop_reason`` (str).
    The ledgers and ``transport_health`` are the already-parsed/already-rolled-up structures.
    ``tooling_health`` + ``empty_recon`` are OPTIONAL (default None → pre-v2 behavior unchanged): when
    both are present they enable the tooling-degraded-empty branch below.
    """
    summary = summary or {}
    findings = int(summary.get("findings_count", 0) or 0)
    engine_rc = summary.get("engine_rc", 0)
    tool_failures = summary.get("tool_failures") or []
    cap_hit = bool(summary.get("cap_hit", False))

    # 1 — we produced accepted findings: that is the outcome, whatever else happened.
    if findings > 0:
        return PRODUCED, None

    # 2 — the engine itself did not complete (crash / non-zero rc) with nothing to show.
    if engine_rc not in (0, None):
        exc = summary.get("exceptions") or []
        if exc:
            detail = f" ({str(exc[0].get('message', ''))[:120]})"
        elif summary.get("stop_reason"):
            detail = f" (stop: {summary['stop_reason']})"
        else:
            detail = ""
        return FAILED, f"engine exited with code {engine_rc}{detail} — the run did not complete"

    # zero findings, engine clean → distinguish a genuinely clean test from a degraded run.
    overall = (transport_health or {}).get("overall") or {}
    block_rate = float(overall.get("block_rate", 0.0) or 0.0)
    worst = overall.get("worst_host")
    blocked = overall.get("status") == "blocked" or block_rate >= HIGH_BLOCK_RATE

    surf_total = _surface_total(surface_ledger)
    cov = _coverage_counts(coverage_ledger)

    # 3a — the transport was blocked: the root cause when present (it explains the empty surface).
    if blocked:
        waf = _worst_host_waf(transport_health, worst)
        pct = round(block_rate * 100)
        return DEGRADED, (
            f"{pct}% of requests to {worst or 'the target'} were blocked/challenged "
            f"({waf or 'unidentified WAF/CDN'}) — coverage is UNRELIABLE; empty findings do "
            f"not mean the target is clean"
        )

    # 3a' — recon came up EMPTY and a recon capability is DEGRADED: the empty surface may be a
    #       tooling gap (a missing primary silently fell back to a lesser tool), not a clean target.
    #       PARALLEL to the transport-blocked case — reached only with zero findings (step 1 already
    #       returned PRODUCED for any run WITH findings), so a tooling degradation can never override
    #       a findings-present outcome. Needs BOTH the empty-recon signal AND a degraded capability.
    degraded_caps = _degraded_capabilities(tooling_health)
    if degraded_caps and _recon_is_empty(empty_recon, surface_ledger):
        cap = degraded_caps[0]
        tail = (f", fell back to '{cap['fallback']}'" if cap.get("fallback")
                else ", and no fallback is available")
        return DEGRADED, (
            f"recon found no live hosts or attack surface AND the '{cap['capability']}' capability is "
            f"degraded (primary '{cap['primary']}' unavailable{tail}) — empty may be a tooling gap, "
            f"not a clean target (see runtime/tooling.json)"
        )

    # 3b — recon discovered no attack surface at all.
    if surface_ledger is not None and surf_total == 0:
        return DEGRADED, (
            "recon discovered no attack surface (0 endpoints/params/forms) — there was nothing "
            "to test (check scope, host discovery and content discovery)"
        )

    # 3c — every routed class was skipped / nothing was attempted.
    if coverage_ledger is not None and cov["attempted"] == 0 and (cov["skipped"] + cov["pending"]) > 0:
        return DEGRADED, (
            f"no vulnerability class was attempted ({cov['skipped']} skipped, "
            f"{cov['pending']} still pending) — no testing was performed"
        )

    # 3d — tool invocations failed during the run.
    if tool_failures:
        n = sum(int(t.get("count", 1) or 1) for t in tool_failures)
        name = tool_failures[0].get("tool", "a tool")
        return DEGRADED, (
            f"{n} tool invocation(s) failed (e.g. {name}) — recon/testing was likely incomplete"
        )

    # 3e — the run ran out of its turn/budget cap before finishing.
    if cap_hit:
        return DEGRADED, (
            "the run hit its turn/budget cap before completing — coverage is partial"
        )

    # 4 — zero findings with positive evidence of testing and a healthy transport → genuinely clean.
    if _was_tested(coverage_ledger, surface_ledger):
        return CLEAN, None

    # otherwise: zero findings and no evidence anything was ever tested — do not claim "clean".
    return DEGRADED, (
        "no evidence that any surface was tested (no attempted categories, no tested surface) — "
        "cannot distinguish a clean target from an untested one"
    )


# --- recon / phase / gate summaries (pure) -----------------------------------
def _live_hosts(host_discovery: dict | None) -> int:
    if not isinstance(host_discovery, dict):
        return 0
    arr = host_discovery.get("live_hosts")
    if not isinstance(arr, list):
        arr = host_discovery.get("hosts")
    if not isinstance(arr, list):
        return 0
    return sum(1 for h in arr if isinstance(h, dict) and h.get("live", True) is not False)


def empty_recon(surface_ledger: dict | None, signals: dict | None,
                host_discovery: dict | None) -> dict:
    surf = _surface_total(surface_ledger)
    sig = len((signals or {}).get("signals") or []) if isinstance(signals, dict) else 0
    hosts_live = _live_hosts(host_discovery)
    return {
        "flag": (surf == 0 and sig == 0 and hosts_live == 0),
        "surface_discovered": surf,
        "signals": sig,
        "hosts_live": hosts_live,
    }


def phase_tally(coverage_ledger: dict | None) -> list[dict]:
    out: list[dict] = []
    if not isinstance(coverage_ledger, dict):
        return out
    for c in coverage_ledger.get("categories") or []:
        if not isinstance(c, dict):
            continue
        out.append({
            "class": str(c.get("id") or c.get("name") or "?"),
            "attempted": str(c.get("status", "")).lower() == "attempted",
            "produced": int(c.get("findings_count", 0) or 0),
        })
    return out


def _coverage_status(coverage_ledger: dict | None) -> str:
    if not isinstance(coverage_ledger, dict):
        return "absent"
    cov = _coverage_counts(coverage_ledger)
    if cov["pending"] > 0:
        return f"{cov['pending']} pending"
    return f"{cov['attempted']} attempted / {cov['skipped']} skipped"


def _surface_status(surface_ledger: dict | None) -> str:
    if not isinstance(surface_ledger, dict):
        return "absent"
    untested = _surface_discovered_untested(surface_ledger)
    tested = _surface_tested_count(surface_ledger)
    if untested > 0:
        return f"{untested} discovered-untested"
    return f"{tested} tested"


def gate_summary(coverage_ledger: dict | None, surface_ledger: dict | None,
                 findings_count: int, recall_audit: dict | None = None) -> dict:
    if isinstance(recall_audit, dict):
        recall = str(recall_audit.get("status") or recall_audit.get("verdict") or "present")
    else:
        recall = "n/a"
    return {
        "coverage": _coverage_status(coverage_ledger),
        "surface": _surface_status(surface_ledger),
        "recall": recall,
        "findings": int(findings_count),
    }


# --- accepted-findings count -------------------------------------------------
def accepted_findings_count(findings: list | None) -> int:
    if not isinstance(findings, list):
        return 0
    return sum(1 for f in findings if isinstance(f, dict)
               and str(f.get("status", "")).lower() in ACCEPTED_STATUSES)


# --- RunSummary -> classify summary dict -------------------------------------
def summary_from_run(summary, findings_count: int, engine_rc: int) -> dict:
    """Normalize an ``autorun.RunSummary`` (or None, for interactive runs that capture no stream)
    into the plain dict ``classify_outcome`` consumes, plus the ``exceptions`` list derived from the
    stream-parse counters and a non-success result subtype."""
    tool_failures = list(getattr(summary, "tool_failures", None) or [])
    subtype = str(getattr(summary, "subtype", "") or "")
    stop_reason = str(getattr(summary, "stop_reason", "") or "")
    non_json = int(getattr(summary, "non_json_lines", 0) or 0)
    non_json_sample = str(getattr(summary, "non_json_sample", "") or "")

    exceptions: list[dict] = []
    if subtype and subtype != "success":
        exceptions.append({"where": "engine-result", "message": f"result subtype '{subtype}'"})
    if non_json:
        msg = f"{non_json} non-JSON stream line(s)"
        if non_json_sample:
            msg += f"; sample: {non_json_sample[:160]}"
        exceptions.append({"where": "stream-parse", "message": msg})

    cap_hit = any(k in f"{subtype} {stop_reason}".lower()
                  for k in ("max_turns", "max-turns", "budget", "limit", "max_tokens"))
    return {
        "findings_count": int(findings_count),
        "engine_rc": int(engine_rc),
        "tool_failures": tool_failures,
        "exceptions": exceptions,
        "cap_hit": cap_hit,
        "stop_reason": stop_reason,
    }


# --- per-leg cause capture (pure) --------------------------------------------
# An autonomous run is many resumed `claude -p` legs (see runloop.drive). When a NON-final leg
# CRASHES (rc != 0), its captured cause used to be thrown away — only the LAST leg's RunSummary
# survived, so a crash loop that finally stopped looked like a generic "no-progress" stall. A
# ``legs[]`` array on the diagnostics record keeps EVERY leg's own outcome (including each crashed
# attempt + any retry/fallback), so the terminal reason can name the real engine cause. This is the
# canonical per-leg entry shape; runloop builds the array (one entry per attempt) and attaches it.
LEG_KINDS = frozenset({"initial", "resume", "retry", "resume-fallback"})


def leg_record(*, attempt: int, kind: str, rc: int, cost: float, summary=None) -> dict:
    """Render ONE leg attempt's pinned diagnostics entry.

    ``attempt`` is the 1-based attempt number within its logical leg; ``kind`` is the leg role
    (``initial`` | ``resume`` | ``retry`` | ``resume-fallback``). ``summary`` is the attempt's
    ``autorun.RunSummary`` (or None). The entry carries the attempt's ``rc``, result ``subtype``,
    ``cost``, ``tool_calls``, the FIRST parsed exception (result-subtype / stream-parse), and the
    first unparseable stream line — enough to attribute a crash to THIS attempt. A bare non-zero exit
    with no stream still yields a synthetic ``engine-exit`` exception so a crash never renders
    cause-less."""
    sm = summary_from_run(summary, 0, int(rc))
    exc_list = sm["exceptions"]
    first_exc = exc_list[0] if exc_list else None
    rc = int(rc)
    if first_exc is None and rc not in (0, None):
        first_exc = {"where": "engine-exit", "message": f"engine exited with code {rc}"}
    non_json_sample = str(getattr(summary, "non_json_sample", "") or "")[:200]
    return {
        "attempt": int(attempt),
        "kind": str(kind),
        "rc": rc,
        "subtype": str(getattr(summary, "subtype", "") or ""),
        "cost": round(float(cost or 0.0), 6),
        "tool_calls": int(getattr(summary, "tool_calls", 0) or 0),
        "first_exception": first_exc,
        "non_json_sample": non_json_sample or None,
    }


def leg_cause(leg: dict | None) -> str:
    """A short human cause for a crashed leg entry (the terminal ``engine-crash`` reason uses it):
    prefer the first exception's message, else the result subtype, else the bare exit code."""
    if not isinstance(leg, dict):
        return "engine crashed (no leg detail captured)"
    exc = leg.get("first_exception")
    if isinstance(exc, dict) and exc.get("message"):
        return str(exc["message"])[:160]
    if leg.get("subtype"):
        return f"result subtype '{leg['subtype']}'"
    return f"engine exited with code {leg.get('rc')}"


# --- assembly (impure glue) --------------------------------------------------
def _load_json(path: Path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return None


def assemble(eng_dir, *, session: str, mode: str, started: str, ended: str,
             engine_rc: int, gate_rc: int | None, summary=None) -> Diagnostics:
    """Read the engagement's artifacts (rate_state / ledgers / findings / recon feeders) and compose
    a full ``Diagnostics`` record, classifying the outcome. Everything is best-effort: a missing or
    malformed file is treated as absent, never fatal."""
    eng_dir = Path(eng_dir)
    rt = eng_dir / "runtime"
    rate_state = _load_json(rt / "rate_state.json") or {}
    coverage_ledger = _load_json(eng_dir / "coverage_ledger.json")
    surface_ledger = _load_json(eng_dir / "surface_ledger.json")
    findings = _load_json(eng_dir / "findings.json")
    signals = _load_json(eng_dir / "signals.json")
    host_discovery = _load_json(eng_dir / "host_discovery.json")
    recall_audit = _load_json(rt / "recall_audit.json")
    tooling = _load_json(rt / "tooling.json")

    findings_count = accepted_findings_count(findings)
    transport_health = transport_rollup(rate_state)
    tooling_health = tooling_rollup(tooling)
    empty = empty_recon(surface_ledger, signals, host_discovery)
    sm = summary_from_run(summary, findings_count, engine_rc)
    outcome, reason = classify_outcome(sm, coverage_ledger, surface_ledger, transport_health,
                                       tooling_health=tooling_health, empty_recon=empty)

    return Diagnostics(
        session=session,
        mode=mode,
        started=started,
        ended=ended,
        engine_rc=int(engine_rc),
        gate_rc=(None if gate_rc is None else int(gate_rc)),
        outcome=outcome,
        degraded_reason=reason,
        findings_count=findings_count,
        tool_failures=sm["tool_failures"],
        exceptions=sm["exceptions"],
        transport_health=transport_health,
        empty_recon=empty,
        phase_tally=phase_tally(coverage_ledger),
        gate_summary=gate_summary(coverage_ledger, surface_ledger, findings_count, recall_audit),
        tooling_health=tooling_health,
    )


# --- persistence -------------------------------------------------------------
def write(eng_dir, record: dict) -> Path:
    """Append ``record`` to ``runtime/diagnostics.json`` ``runs[]`` (creating the document on first
    write) and append redacted human lines to ``runtime/error.log``. Returns the diagnostics path."""
    eng_dir = Path(eng_dir)
    runtime = eng_dir / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    diag_path = runtime / "diagnostics.json"

    doc = _load_json(diag_path)
    if not isinstance(doc, dict):
        doc = {}
    runs = doc.get("runs")
    if not isinstance(runs, list):
        runs = []
    runs.append(record)
    doc = {
        "version": DIAG_SCHEMA_VERSION,
        "engagement": doc.get("engagement") or eng_dir.name,
        "generated_at": _now_iso(),
        "runs": runs,
    }
    diag_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    _append_error_log(runtime / "error.log", record)
    return diag_path


def _append_error_log(path: Path, record: dict) -> None:
    """One redacted, timestamped human line per notable event (outcome, degraded transport, tool
    failures, exceptions). Append-only; never raises."""
    ts = record.get("ended") or _now_iso()
    sess = str(record.get("session", ""))[:8]
    lines: list[str] = []

    head = (f"outcome={record.get('outcome')} session={sess} mode={record.get('mode')} "
            f"findings={record.get('findings_count')} engine_rc={record.get('engine_rc')}")
    if record.get("degraded_reason"):
        head += f" :: {record['degraded_reason']}"
    lines.append(head)

    overall = (record.get("transport_health") or {}).get("overall") or {}
    if overall.get("status") in ("degraded", "blocked"):
        pct = round(float(overall.get("block_rate", 0.0) or 0.0) * 100)
        lines.append(f"transport {overall.get('status')}: {pct}% blocked/challenged overall, "
                     f"worst_host={overall.get('worst_host')}")

    for tf in record.get("tool_failures") or []:
        lines.append(f"tool_failure tool={tf.get('tool')} exit_code={tf.get('exit_code')} "
                     f"phase={tf.get('phase')} count={tf.get('count')}")
    for ex in record.get("exceptions") or []:
        lines.append(f"exception where={ex.get('where')} :: {ex.get('message', '')}")

    for ln in lines:
        auditmod.append_line(path, auditmod.redact_text(f"[{ts}] {ln}"))
