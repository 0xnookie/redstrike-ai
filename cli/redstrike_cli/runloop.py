"""Autonomous resume loop — drive an engagement to completion across resumed `claude -p` legs.

The autonomous path is NOT a single capped invocation: a full pentest (recon + ~40 vuln
categories, each with a context feeder + executor + an independent verify subagent + ledger
bookkeeping + re-convergence + chaining + report) cannot finish inside one `--max-turns`
window. This module runs the first invocation, then RESUMES the same session over and over —
building a fresh continue-prompt from the coverage ledger each time — until the engagement is
report-ready OR a hard ceiling trips. The whole loop runs in ONE process, so the console's
pid-liveness check and the `autorun.jsonl` boundary markers keep working unchanged.

COMPLETION CONTRACT (why a leg ends the loop)
    done                 gate.verify(repo, eng_dir) == 0 — complete + coverage-accounted + report-ready.
                         gate.verify now also carries the cross-model EXHAUSTION-ADVERSARY gate (a report
                         is report-ready only once the model-pinned adversary wrote a `no_gaps_found`
                         verdict to runtime/exhaustion_review.json). So an engagement whose adversary
                         returned `found_gaps` (or was never run) is NOT `done`: _gate_done stays False,
                         the continue-prompt tells the next leg to spawn the adversary and re-drive the
                         gaps it named, and the loop resumes. This stays BOUNDED — the adversary can
                         always return `no_gaps_found` (it may close a genuinely-unclosable gap with a
                         named blocker), and a gap that never closes makes no progress and is stopped by
                         the no-progress breaker / the invocation + budget + wall-clock ceilings with an
                         honest "partial" (annotate_record downgrades a non-done run), never spinning.
    budget-exhausted     the cumulative cost reached the TOTAL budget (remaining <= floor).
    max-invocations      the resume cap (default 10, env REDSTRIKE_MAX_INVOCATIONS) was hit.
    wall-clock           the wall-clock backstop (env REDSTRIKE_MAX_WALL_SECONDS) was hit.
    blocked-on-approval  only deferred pending-approval items remain and the leg made no other
                         progress — stop (the operator approves in the console, then relaunches
                         `--resume`); never spin waiting on a human.
    no-progress          two consecutive legs made no progress (identical remaining-pending
                         coverage set AND no new findings AND ~zero new tool calls) — a stuck run.

The budget is GLOBAL: each leg is passed `--max-budget-usd = remaining` (never more than what is
left of the total), and `--max-turns` stays PER-leg (the loop supplies more total turns by
resuming). Only the first invocation honors an operator `--resume`; every later leg resumes the
stable session minted once in `prepare_runtime` (we never re-`prepare`, which would mint a new id).

The pure pieces (`made_progress`, `pending_ids`, `continue_prompt`, `loop_degraded_reason`,
`annotate_record`) are unit-tested directly; `drive` is the glue that runs legs via the engine.
"""
from __future__ import annotations

import concurrent.futures
import copy
import datetime as _dt
import json
import os
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from . import diagnostics
from . import gate as gatemod
from . import ui
from .engines import RunResult

# --- stop reasons ------------------------------------------------------------
DONE = "done"
BUDGET_EXHAUSTED = "budget-exhausted"
MAX_INVOCATIONS = "max-invocations"
WALL_CLOCK = "wall-clock"
BLOCKED_ON_APPROVAL = "blocked-on-approval"
NO_PROGRESS = "no-progress"
ENGINE_CRASH = "engine-crash"          # a leg's `claude -p` exited rc!=0 and could not be recovered
                                       # (retries + fresh-session fallback exhausted). DISTINCT from
                                       # no-progress: an ENGINE failure, never "the run is stuck".

# --- ceilings / thresholds ---------------------------------------------------
DEFAULT_MAX_INVOCATIONS = 10            # env REDSTRIKE_MAX_INVOCATIONS
DEFAULT_MAX_WALL_SECONDS = 24 * 3600    # env REDSTRIKE_MAX_WALL_SECONDS (generous backstop)
BUDGET_FLOOR = 0.25                     # stop once remaining global budget <= this
NO_PROGRESS_TOOLCALLS = 1              # "~zero new tool calls" for a leg == did nothing
STALL_LIMIT = 2                        # consecutive no-progress legs that trip the breaker
DEFAULT_CRASH_RETRIES = 2              # env REDSTRIKE_CRASH_RETRIES — bounded retries of a CRASHED
                                       # leg (rc!=0) with backoff BEFORE it counts as a failure
RETRY_BACKOFF_SECONDS = 2.0           # env REDSTRIKE_RETRY_BACKOFF_SECONDS — linear per-attempt base


# --- small env helpers -------------------------------------------------------
def _env_int(name: str, default: int) -> int:
    try:
        v = os.environ.get(name)
        return int(v) if v not in (None, "") else default
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        v = os.environ.get(name)
        return float(v) if v not in (None, "") else default
    except (TypeError, ValueError):
        return default


# --- ledger reads (fail-safe) ------------------------------------------------
def _read_json(path: Path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return None


def read_ledger(eng_dir: Path) -> dict | None:
    return _read_json(Path(eng_dir) / "coverage_ledger.json")


def pending_ids(ledger: dict | None) -> frozenset:
    """Category ids still `pending` (routed but never run) — the remaining-work set the
    no-progress breaker compares across legs."""
    if not isinstance(ledger, dict):
        return frozenset()
    out = set()
    for c in ledger.get("categories") or []:
        if isinstance(c, dict) and str(c.get("status", "")).lower() == "pending":
            cid = c.get("id") or c.get("name")
            if cid:
                out.add(str(cid))
    return frozenset(out)


def redrivable_ids(ledger: dict | None) -> frozenset:
    """Category ids that are NOT yet genuinely run — status `pending` OR `blocked`. This is the set
    that must empty before the engagement is DONE. `blocked` is included on purpose: an autonomous
    engine can over-cautiously mark non-destructive vulnerability DETECTION as "approval-gated" and
    `blocked` (observed), and the coverage gate then PASSES (blocked counts as accounted) even with
    no report — so `gate.verify == 0` alone would falsely call a recon-only run "done". Treating
    `blocked` as re-drivable makes the loop resume and actually run those categories; a category that
    is legitimately blocked (e.g. needs test accounts) simply makes no progress and is caught by the
    no-progress breaker, which stops with an honest "coverage partial" outcome rather than a false
    "clean"."""
    if not isinstance(ledger, dict):
        return frozenset()
    out = set()
    for c in ledger.get("categories") or []:
        if isinstance(c, dict) and str(c.get("status", "")).lower() in ("pending", "blocked"):
            cid = c.get("id") or c.get("name")
            if cid:
                out.add(str(cid))
    return frozenset(out)


def outstanding_categories(ledger: dict | None) -> list[dict]:
    """Categories the continue-prompt should name: still `pending`, still `blocked` (re-drive its
    non-destructive detection — see `redrivable_ids`), OR `attempted` with zero findings and an
    escalation ladder that is not obviously exhausted (so an empty-but-signalled surface gets
    another, deeper pass)."""
    if not isinstance(ledger, dict):
        return []
    out: list[dict] = []
    for c in ledger.get("categories") or []:
        if not isinstance(c, dict):
            continue
        st = str(c.get("status", "")).lower()
        if st in ("pending", "blocked"):
            out.append(c)
        elif st == "attempted" and int(c.get("findings_count", 0) or 0) == 0:
            # attempted-but-empty: worth another pass only while the ladder isn't clearly spent.
            if len(c.get("escalations") or []) < 4:
                out.append(c)
    return out


def _findings_total(eng_dir: Path) -> int:
    """A monotone finding signal for progress detection: the ledger's summed findings_count,
    floored by a root findings.json length when present (the ledger may lag the writes)."""
    total = 0
    ledger = read_ledger(eng_dir)
    if isinstance(ledger, dict):
        for c in ledger.get("categories") or []:
            if isinstance(c, dict):
                total += int(c.get("findings_count", 0) or 0)
    fj = _read_json(Path(eng_dir) / "findings.json")
    if isinstance(fj, list):
        total = max(total, len(fj))
    return total


def pending_approvals_count(eng_dir: Path) -> int:
    """How many deferred actions await operator approval (runtime/approvals_pending.json is a
    list; tolerate the console's {"pending": [...]} shape too)."""
    data = _read_json(Path(eng_dir) / "runtime" / "approvals_pending.json")
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        return len(data.get("pending") or [])
    return 0


# --- chain-pressure (the SubagentStop chain_pressure hook writes runtime/chain-pending.json) ----------
# A quality net, not a coverage gate: accepted findings in FEEDER classes (open-redirect/cors/info-
# disclosure/csrf/…) that carry no chain reference are LOW alone and only earn their rating once chained.
# The hook flags them; the loop keeps the engagement OUT of report-ready (blocks DONE) and tells the next
# leg to run attack-chain-discovery on exactly those feeders. BOUNDED: the hook drops a feeder once chaining
# has been ATTEMPTED (it became a chain step, or was recorded in probes.json), so one chainer pass drains it;
# if the engine never runs the chainer, the loop makes no progress and the no-progress breaker (+ the hard
# ceilings) stops it. Fail-safe reads: an unreadable/absent file is simply empty.

def read_chain_pending(eng_dir: Path) -> dict | None:
    return _read_json(Path(eng_dir) / "runtime" / "chain-pending.json")


def chain_pending_feeders(eng_dir: Path) -> list[dict]:
    """The flagged feeder entries from runtime/chain-pending.json (each {id, class, title, asset, anchors}),
    or [] when the file is absent/empty/unreadable."""
    doc = read_chain_pending(eng_dir)
    if not isinstance(doc, dict):
        return []
    out = [p for p in (doc.get("pending") or []) if isinstance(p, dict)]
    return out


def chain_pending_ids(eng_dir: Path) -> frozenset:
    """Finding ids of the still-pending feeders — the set that must empty before report-ready."""
    out = set()
    for p in chain_pending_feeders(eng_dir):
        fid = p.get("id") or p.get("class")
        if fid:
            out.add(str(fid))
    return frozenset(out)


# --- progress snapshot (pure) ------------------------------------------------
@dataclass(frozen=True)
class Snapshot:
    pending: frozenset = frozenset()
    findings: int = 0
    tool_calls: int = 0   # tool calls made DURING this leg (per-leg, from the RunSummary)


def snapshot(eng_dir: Path, res) -> Snapshot:
    s = getattr(res, "summary", None)
    try:
        tool_calls = int(getattr(s, "tool_calls", 0) or 0)
    except (TypeError, ValueError):
        tool_calls = 0
    return Snapshot(
        pending=pending_ids(read_ledger(eng_dir)),
        findings=_findings_total(eng_dir),
        tool_calls=tool_calls,
    )


def made_progress(prev: Snapshot | None, cur: Snapshot,
                  *, tool_threshold: int = NO_PROGRESS_TOOLCALLS) -> bool:
    """Did THIS leg advance the engagement? A leg progressed if it did real tool work, produced
    a finding, or moved the remaining-pending set. On the first leg (no baseline) only the
    absolute signals (tool work / a finding) count."""
    if cur.tool_calls > tool_threshold:
        return True
    if prev is None:
        return cur.findings > 0
    if cur.findings > prev.findings:
        return True
    if cur.pending != prev.pending:
        return True
    return False


# --- hunt-plan consumption (deterministic ordering) --------------------------
# The strategist emits <engagement>/hunt_plan.json (schema skills/_contract/hunt_plan.schema.json): a
# RANKED queue over the routed classes plus a per-class depth_budget. It is a ranking artifact, never a
# ledger — coverage.py stays the SOLE ledger owner. The continue-prompt CONSUMES it to order the resume
# work by `rank` and to tell each class how much depth (standard/deep + a diversity pass) it is worth, so
# the resume legs drive the same ranked, model-diverse wave order the orchestrator SKILL (§2b/§2.5) runs —
# instead of walking the ledger in arbitrary order. Absent/malformed plan ⇒ fall back to ledger order
# (ordering is an efficiency aid, never a gate: its absence can never block or shrink the hunt).

def read_hunt_plan(eng_dir: Path) -> dict | None:
    return _read_json(Path(eng_dir) / "hunt_plan.json")


def _plan_rank_map(plan: dict | None) -> dict:
    """{class_id -> (rank:int|None, depth_tier:str|None, diversity_pass:bool)} from hunt_plan.json's
    queue. Tolerant of a missing/malformed plan or entry (skips it)."""
    out: dict = {}
    if not isinstance(plan, dict):
        return out
    for e in plan.get("queue") or []:
        if not isinstance(e, dict):
            continue
        cid = e.get("class")
        if not cid:
            continue
        try:
            rank = int(e["rank"]) if e.get("rank") is not None else None
        except (TypeError, ValueError):
            rank = None
        db = e.get("depth_budget") if isinstance(e.get("depth_budget"), dict) else {}
        tier = db.get("tier")
        div = bool(db.get("diversity_pass"))
        out[str(cid)] = (rank, tier, div)
    return out


def _lookup_plan(cid: str, rank_map: dict):
    """Resolve a coverage category id to its plan (rank, depth_tier, diversity_pass). Exact match first;
    then a hyphen-family fallback (plan 'xss' covers 'xss-reflected'; 'ssrf' covers 'ssrf-cloud'), picking
    the lowest-ranked family match deterministically. (None, None, False) when the plan doesn't rank it."""
    if cid in rank_map:
        return rank_map[cid]
    best = None
    for cls, val in rank_map.items():
        if cid.startswith(cls + "-") or cls.startswith(cid + "-"):
            if best is None or (val[0] is not None and (best[0] is None or val[0] < best[0])):
                best = val
    return best if best is not None else (None, None, False)


def order_outstanding(outstanding: list, plan: dict | None) -> list:
    """Order the outstanding coverage categories into the hunt sequence the WAVE loop consumes: ascending
    hunt_plan `rank` (rank 1 first — the batching the orchestrator fans out wave by wave), with classes the
    plan does not rank kept in their original ledger order AFTER the ranked ones (stable). Each returned
    dict is the original category annotated with `_rank`, `_depth` (depth_budget.tier) and `_diversity`
    (depth_budget.diversity_pass) so the prompt can state each class's rank + depth budget."""
    rank_map = _plan_rank_map(plan)
    inf = float("inf")
    annotated = []
    for i, c in enumerate(outstanding):
        if not isinstance(c, dict):
            continue
        cid = str(c.get("id") or c.get("name") or "")
        rank, tier, div = _lookup_plan(cid, rank_map)
        item = dict(c)
        item["_rank"], item["_depth"], item["_diversity"] = rank, tier, div
        annotated.append((rank if rank is not None else inf, i, item))
    annotated.sort(key=lambda t: (t[0], t[1]))
    return [item for _, _, item in annotated]


def _depth_annotation(c: dict) -> str:
    """ ` [rank 3 · depth deep · diversity pass]` for a plan-ranked class, or '' when the plan is absent."""
    parts = []
    if c.get("_rank") is not None:
        parts.append(f"rank {c['_rank']}")
    if c.get("_depth"):
        parts.append(f"depth {c['_depth']}")
    if c.get("_diversity"):
        parts.append("diversity pass")
    return f" [{' · '.join(parts)}]" if parts else ""


# --- continue-prompt (pure) --------------------------------------------------
def _chain_pending_clause(eng_dir: Path, *, max_list: int = 12) -> str:
    """A resume-prompt directive naming the ACCEPTED feeder findings that still lack a chain (from
    runtime/chain-pending.json), so the next leg dispatches attack-chain-discovery on them BEFORE
    report-ready. Empty string when nothing is pending."""
    feeders = chain_pending_feeders(eng_dir)
    if not feeders:
        return ""
    bullets = []
    for f in feeders[:max_list]:
        fid = f.get("id") or "?"
        cls = f.get("class") or "?"
        anchors = f.get("anchors") or []
        anchor = f"; first anchor: {anchors[0]}" if anchors else ""
        bullets.append(f"  - {fid} ({cls}){anchor}")
    more = len(feeders) - min(len(feeders), max_list)
    if more > 0:
        bullets.append(f"  - …and {more} more in runtime/chain-pending.json")
    return (
        " CHAIN-PRESSURE: these ACCEPTED findings are in FEEDER classes and still lack a chain reference — "
        "they are LOW/informational alone and must be chained before the engagement is report-ready. Run "
        "`attack-chain-discovery` on EXACTLY these feeders (consult skills/attack-chain-discovery/refs/"
        "chain_anchors.md for each anchor; gate + run the ONE Tier-2 probe per missing leg under its "
        "*-verify reviewer); promote a chain only on an accepted leg, else record the dropped hypothesis in "
        "probes.json. Do not reach report-ready while runtime/chain-pending.json is non-empty:\n"
        + "\n".join(bullets)
    )


def continue_prompt(engagement_id: str, eng_dir: Path, *, max_list: int = 25) -> str:
    """The resume prompt for leg 2+: name exactly what's left from the coverage ledger, ORDERED by the
    hunt_plan ranking (§2.5), and tell the engine to continue the orchestrator pipeline on those as ranked
    model-diverse waves, then re-converge / recall-audit / chain / report — without repeating completed
    work. Falls back to a generic continue when the ledger can't be read, and to ledger order when no
    hunt_plan exists."""
    ledger = read_ledger(eng_dir)
    outstanding = order_outstanding(outstanding_categories(ledger), read_hunt_plan(eng_dir))
    head = (
        f"Continue Redstrike engagement '{engagement_id}' from where the previous invocation "
        f"stopped (it hit its per-invocation turn cap, not the end of the work). Authorization "
        f"and scope are already recorded (RoE appended) — §0 is SATISFIED, do not re-ask. Do NOT "
        f"repeat completed work: consult coverage_ledger.json and skip every category already done "
        f"('attempted' with findings, 'skipped', or 'n/a')."
    )
    chain_clause = _chain_pending_clause(eng_dir)
    if not outstanding:
        return (
            head + " No specific categories were parseable as outstanding — finish any remaining "
            "coverage per coverage_ledger.json (run non-destructive detection for any category still "
            "'pending' or 'blocked' — detection and benign PoCs are NOT gated), then re-converge, run "
            "the recall-audit, compose attack chains over accepted findings, THEN spawn the model-pinned "
            "cross-model `exhaustion-adversary` subagent to DISPROVE 'engagement complete' (it writes "
            "runtime/exhaustion_review.json): on a `found_gaps` verdict, re-drive EXACTLY the "
            "categories/surfaces it names and re-run it; only a `no_gaps_found` verdict is report-ready — "
            "then write the report. "
            "Only a genuine exploitation / destructive / RCE command defers for operator approval; "
            "when one does, record it, skip that one step, and CONTINUE the rest — never halt the "
            "whole run at a gate."
            + chain_clause
        )
    shown = outstanding[:max_list]
    bullets = []
    for c in shown:
        cid = c.get("id") or c.get("name") or "?"
        st = str(c.get("status", "")).lower()
        if st == "pending":
            tag = "pending — run it now"
        elif st == "blocked":
            tag = "blocked as approval-gated — run its NON-DESTRUCTIVE detection now (detection is not gated)"
        else:
            tag = "attempted, 0 findings — escalate deeper"
        bullets.append(f"- {cid}{_depth_annotation(c)} ({tag})")
    more = len(outstanding) - len(shown)
    if more > 0:
        bullets.append(f"- …and {more} more still outstanding in coverage_ledger.json")
    return (
        head
        + " The following vulnerability categories are still OUTSTANDING, in HUNT-PLAN RANK ORDER "
        "(rank 1 first; each class's depth budget is noted):\n"
        + "\n".join(bullets)
        + "\nInvoke the redstrike orchestrator skill and run the orchestrator pipeline on exactly "
        "these, in the listed rank order as CONCURRENT model-diverse WAVES (§2b). Make each class a "
        "DISTINCTLY-LABELLED, INDEPENDENTLY-REVIEWED unit in the run stream: per class, FIRST emit a "
        "TaskCreate whose subject LEADS with that class's executor skill slug as a literal token (e.g. "
        "'xss-reflected: …', 'sqli-inband: …', 'idor: …') so the console Task-flow view renders a distinct "
        "per-class node for it — do NOT fold multiple classes into one umbrella 'hunt everything' task. "
        "Per wave, spawn the executors as parallel subagents on a mix of models (higher-rank / deep classes "
        "on the stronger model, the rest on the cheaper one; run the diversity pass for any class so noted), "
        "each running its context feeder (if any) → executor → its independent '<skill>-verify' reviewer "
        "subagent (spawn the reviewer as its OWN Agent, subagent_type '<skill>-verify') and writing its own "
        "skill's findings.json. The '*-verify' gate is NON-SKIPPABLE — only reviewer-ACCEPTED findings "
        "advance, and do NOT collapse classes into anonymous 'general-purpose' family batches with no class "
        "name in the stream (that hides which classes ran and is where the per-class verify gate gets "
        "skipped). After each wave, reconcile the ledgers by CALLING the scripts (never "
        "hand-editing): scripts/coverage.py --mark, scripts/surface.py --mark, scripts/dedup.py. "
        "Vulnerability DETECTION and benign PoCs are NON-destructive and are NOT gated — run them now; a "
        "category previously left 'blocked' as approval-gated must have its non-destructive detection run. "
        "Only a genuine exploitation / destructive / RCE command defers at the scope gate: when one does, "
        "it is queued in runtime/approvals_pending.json for the operator — record it, skip that one step, "
        "and CONTINUE the rest; never halt the whole run at a gate. When no categories remain outstanding, "
        "re-converge, run the recall-audit, compose attack chains over accepted findings, THEN spawn the "
        "model-pinned cross-model `exhaustion-adversary` subagent to DISPROVE 'engagement complete' (it "
        "writes runtime/exhaustion_review.json): on a `found_gaps` verdict, re-drive EXACTLY the "
        "categories/surfaces it names and re-run it; only a `no_gaps_found` verdict reaches report-ready — "
        "then write the report."
        + chain_clause
    )


# --- diagnostics overlay (pure) ----------------------------------------------
def loop_degraded_reason(reason: str, *, invocations: int, cumulative_cost: float,
                         max_budget: float, pending_count: int, pending_approvals: int,
                         crash_cause: str | None = None) -> str | None:
    """A human, honest one-liner for why the WHOLE looped run ended (None when it completed)."""
    if reason == DONE:
        return None
    if reason == ENGINE_CRASH:
        cause = f" — {crash_cause}" if crash_cause else ""
        return (f"stopped after {invocations} invocation(s): the engine CRASHED and could not be "
                f"recovered (bounded retries + a fresh-session fallback were exhausted){cause}; "
                f"{pending_count} category/ies still outstanding. This is an ENGINE failure, NOT a "
                f"stuck run — see runtime/error.log + runtime/diagnostics.json legs[], fix the cause, "
                f"then relaunch with --resume")
    if reason == BUDGET_EXHAUSTED:
        return (f"stopped after {invocations} invocation(s): the global budget (${max_budget:.2f}) "
                f"was exhausted (${cumulative_cost:.2f} spent) with {pending_count} category/ies "
                f"still outstanding — coverage is partial, relaunch with a higher --max-budget-usd")
    if reason == MAX_INVOCATIONS:
        return (f"stopped after the max of {invocations} resume invocation(s) with {pending_count} "
                f"category/ies still outstanding — coverage is partial (raise REDSTRIKE_MAX_INVOCATIONS "
                f"to allow more legs)")
    if reason == WALL_CLOCK:
        return (f"stopped after {invocations} invocation(s): the wall-clock ceiling was hit with "
                f"{pending_count} category/ies still outstanding — coverage is partial")
    if reason == NO_PROGRESS:
        return (f"stopped after {invocations} invocation(s): two consecutive resumes made no "
                f"progress ({pending_count} category/ies still outstanding) — the run is stuck")
    if reason == BLOCKED_ON_APPROVAL:
        return (f"run paused after {invocations} invocation(s): {pending_approvals} action(s) await "
                f"operator approval and nothing else advanced — approve in the console, then "
                f"relaunch with --resume")
    return None


# --- audit-close artifacts (fix: the completeness gates ran dark) ------------
# When the autorun pipeline crashed and a hunter swarm wrote findings.json / report.md directly (the
# shopware-2026-11-19 failure), reporting never ran, so no report/findings_consolidated.json existed, the
# coverage ledger stayed silent-green at 0, the surface ledger's code-audit slice was never populated, and
# the hard completeness gates all early-returned []. These close-steps make the ledgers + report reflect
# reality at audit close so the gates can SEE the engagement — each is BEST-EFFORT and never alters the
# loop outcome.

def _scope_is_source(eng_dir: Path) -> bool:
    """True when this engagement was granted SOURCE access (white-box) — runtime/scope.json carries a
    `source_repo` block (scope.build_projection writes it from scope.yaml's `source:`)."""
    d = _read_json(Path(eng_dir) / "runtime" / "scope.json")
    return isinstance(d, dict) and isinstance(d.get("source_repo"), dict) and bool(d["source_repo"])


def _authoritative_findings(eng_dir: Path) -> list:
    """The engagement's single source of truth for findings: the top-level findings.json when present
    (the shared vault the swarm/executors write), else the per-skill `*/findings.json` union. Mirrors the
    completion gate's discovery so the materialized report matches what verify scans."""
    eng = Path(eng_dir)

    def _flat(doc):
        if isinstance(doc, list):
            return [f for f in doc if isinstance(f, dict)]
        if isinstance(doc, dict):
            return [f for f in (list(doc.get("findings") or []) + list(doc.get("attack_chains") or []))
                    if isinstance(f, dict)]
        return []

    root = _read_json(eng / "findings.json")
    if root is not None:
        return _flat(root)
    acc = []
    for p in sorted(eng.glob("*/findings.json")):
        acc.extend(_flat(_read_json(p)))
    return acc


def _materialize_report(eng_dir: Path, findings: list) -> bool:
    """Safety net (fix #2): write report/findings_consolidated.json from the authoritative findings when
    reporting was SKIPPED — so (a) the completeness gates arm (report-present), and (b) the authoritative
    set lands where verify scans. Conservative: NEVER clobbers an existing report, and no-ops when there
    are no findings. Returns True only when it wrote the file."""
    eng = Path(eng_dir)
    out = eng / "report" / "findings_consolidated.json"
    if out.is_file() or not findings:
        return False
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        plain = [f for f in findings if not (f.get("composite") or f.get("_composite"))]
        chains = [f for f in findings if (f.get("composite") or f.get("_composite"))]
        doc = {
            "generated": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "source": "runloop close (reporting was skipped — materialized from authoritative findings)",
            "findings": plain,
            "attack_chains": chains,
        }
        out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        return True
    except Exception:
        return False


def close_artifacts(repo: Path, eng_dir: Path, *, emit=None) -> None:
    """Reconcile the ledgers + report with reality at audit close so the completeness gates can SEE the
    engagement. Best-effort end to end — any failure degrades to a no-op and never breaks the flow:
      1. scope.source: run `surface.py --plan` so the code-audit surface slice is populated even if the LLM
         skipped the surface step (idempotent merge — preserves tested/skipped progress);
      2. `coverage.py --close`: reconcile coverage_ledger.json findings_count+status from the authoritative
         findings (a white-box run attributes them to code-audit) so it stops reading silent-green at 0;
      3. materialize report/findings_consolidated.json when reporting was skipped (so the gates arm and the
         authoritative set lands where verify scans)."""
    emit = emit or (lambda _line: None)
    eng, repo = Path(eng_dir), Path(repo)
    source = _scope_is_source(eng)

    if source:
        script = repo / "scripts" / "surface.py"
        if script.is_file():
            try:
                subprocess.run([sys.executable, str(script), "--plan", "--engagement", str(eng)],
                               cwd=str(repo), check=False, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=120)
            except Exception:
                pass

    cov = repo / "scripts" / "coverage.py"
    if cov.is_file():
        cmd = [sys.executable, str(cov), "--close", "--engagement", str(eng)]
        if source:
            cmd += ["--source-category", "code-audit"]
        try:
            subprocess.run(cmd, cwd=str(repo), check=False, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=60)
        except Exception:
            pass

    try:
        findings = _authoritative_findings(eng)
        if _materialize_report(eng, findings):
            emit(ui.info(f"reporting was skipped — materialized report/findings_consolidated.json from "
                         f"{len(findings)} authoritative finding(s) so the completeness gates arm at close"))
    except Exception:
        pass


# --- deterministic plan pre-steps (#4: don't let the model route around building the ledgers) ----------
# The hunt_plan ORDERING (continue_prompt) and the completeness gates can only work off ledgers that
# actually exist, and "a step the workflow can route around isn't real" — the same lesson that moved the
# gates out of the prompt. So before each RESUME leg the loop runs the plan scripts ITSELF rather than
# trusting the model to: surface.py --plan is an IDEMPOTENT merge (it preserves tested/skipped progress and
# only folds in newly-discovered surface — safe + beneficial on every resume), while coverage.py --plan is
# run ONLY when the coverage ledger is still MISSING, because it REBUILDS the ledger (non-idempotent) and
# re-running it over an existing ledger would wipe the attempted/findings_count progress the resume loop
# depends on. Both are best-effort: a missing script / repo / timeout degrades to a no-op and never breaks
# the leg. coverage.py remains the SOLE ledger owner — this CALLS its writer, never edits the JSON.

def _run_script(repo: Path, rel: str, args: list, *, timeout: int = 120) -> bool:
    """Run scripts/<rel> under the current interpreter, best-effort. Returns True iff it was launched (the
    script exists and no exception escaped); the script's own rc is intentionally ignored."""
    script = Path(repo) / "scripts" / rel
    if not script.is_file():
        return False
    try:
        subprocess.run([sys.executable, str(script), *args], cwd=str(repo), check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
        return True
    except Exception:
        return False


def run_plan_steps(repo: Path, eng_dir: Path, *, emit=None) -> None:
    """Deterministic plan pre-steps the resume loop runs for itself (see the section note above). Entirely
    best-effort — never raises, never alters the loop outcome."""
    emit = emit or (lambda _l: None)
    eng, repo = Path(eng_dir), Path(repo)
    # 1. surface ledger — idempotent merge: safe on every resume, folds in surface discovered since.
    _run_script(repo, "surface.py", ["--plan", "--engagement", str(eng)])
    # 2. coverage ledger — CREATE it only when absent; a rebuild over an existing ledger would clobber the
    #    attempted/findings_count progress the loop reads. (On resume it normally already exists.)
    if not (eng / "coverage_ledger.json").is_file():
        args = ["--plan", "--engagement", str(eng)]
        sig = eng / "signals.json"
        if sig.is_file():
            args += ["--signals", str(sig)]
        _run_script(repo, "coverage.py", args)


def annotate_record(record: dict, loop: "LoopResult") -> dict:
    """Overlay the loop's whole-run stop reason onto a diagnostics record so the OUTCOME is honest:
    a budget-truncated / max-invocation / stuck / blocked run is degraded (coverage partial), not
    'clean'. Leaves a cleanly completed, gate-clear run (reason==done, gate_rc==0) exactly as
    classify_outcome decided.

    Also BINDS the outcome to the post-run gate (fix #9): when the completion/coverage gate REFUSED the
    engagement (a non-zero `gate_rc` in the record — an open ledger / untested source surface /
    unreconciled candidate), a 'complete/clean' outcome must not be emitted. A would-be produced-findings
    / clean-tested outcome is downgraded to degraded-empty with the gate-refusal reason, so the console
    (which reads the latest run's outcome + degraded_reason) shows the refusal instead of a false green —
    a human/subagent swarm cannot narrate 'hardened' past an open gate."""
    gate_rc = record.get("gate_rc")
    if isinstance(gate_rc, int) and gate_rc != 0 and record.get("outcome") in (
            diagnostics.PRODUCED, diagnostics.CLEAN):
        note = ("the completion/coverage gate REFUSED this engagement (open ledger / untested source "
                "surface / unreconciled candidate) — findings may exist but the audit is NOT report-ready; "
                "run `redstrike verify <eng>` for the gate ledger")
        prior = str(record.get("degraded_reason") or "").strip()
        record["outcome"] = diagnostics.DEGRADED
        record["degraded_reason"] = f"{prior} · {note}" if prior else note

    # Per-leg cause capture: surface EVERY leg attempt's own outcome (rc / subtype / cost / tool_calls
    # / first-exception) so a failing NON-final leg's cause survives — previously only the last leg's
    # RunSummary was kept. Attached whenever the loop captured any legs (new autonomous path only).
    if getattr(loop, "legs", None):
        record["legs"] = list(loop.legs)

    if loop.reason == DONE:
        return record
    if record.get("outcome") == diagnostics.PRODUCED:
        return record
    # An unrecoverable engine crash is a FAILED run (distinct from degraded-empty): the run did not
    # complete because the ENGINE died, not because the surface was empty or the breaker tripped. Carry
    # the captured crash cause and do NOT let the generic stop_detail downgrade it to degraded.
    if loop.reason == ENGINE_CRASH:
        record["outcome"] = diagnostics.FAILED
        if loop.stop_detail:
            record["degraded_reason"] = loop.stop_detail
        return record
    if loop.stop_detail:
        record["outcome"] = diagnostics.DEGRADED
        record["degraded_reason"] = loop.stop_detail
    return record


# --- loop result -------------------------------------------------------------
@dataclass
class LoopResult:
    result: RunResult                 # combined: last leg's summary, cumulative cost, first→last bounds
    invocations: int = 0
    cumulative_cost: float = 0.0
    reason: str = DONE
    stop_detail: str | None = None
    budgets: list = field(default_factory=list)   # the --max-budget-usd passed to each leg
    pending_count: int = 0
    legs: list = field(default_factory=list)      # per-attempt cause capture (diagnostics.leg_record)


def _cost_of(res) -> float:
    s = getattr(res, "summary", None)
    try:
        return float(getattr(s, "cost_usd", 0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _gate_done(gate_verify, repo: Path, eng_dir: Path) -> bool:
    """Completion check — fail-safe: any throw means 'cannot confirm done', so the caps and the
    no-progress breaker remain the backstops rather than the loop crashing."""
    try:
        return gate_verify(repo, eng_dir) == 0
    except Exception:
        return False


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


# --- single-leg execution + crash recovery -----------------------------------
# WAVE-2 SEAM — the atomic engine-leg primitives shared by the single-session resumer (`drive`) and the
# multi-process worker pool (`drive_pool`). Wave 2 shipped 2a (the in-process multi-model hunter swarm: the
# orchestrator SKILL fans executors out as concurrent `Agent`/Task subagents per rank wave, §2b, with the
# resume legs ordered by hunt_plan rank — see `continue_prompt`) AND 2b (this module's `drive_pool`: an
# N-PROCESS scheduler that runs several `claude -p` legs at once — one SHARD per `--shard-models` entry,
# each on its own model + its own session — for a cheap model-diversity pass that raises recall). Both are
# built on these two primitives: `_execute_leg` is the ATOMIC unit of engine work (the per-shard call a pool
# fans out) and `_run_leg` wraps it with the rc-branching / bounded-retry / resume-fallback that every shard
# reuses for free. Keep them factored OUT of `drive`/`drive_pool` — do NOT inline them back: `drive` composes
# `_run_leg` across resumed legs of ONE session; `drive_pool` composes it across concurrent shards. The
# post-leg/post-wave completion contract is itself factored into `_decide_stop` so the two drivers can never
# diverge on when the engagement is DONE / blocked / stuck.

@dataclass
class _LegOutcome:
    """The result of running ONE logical leg (its first attempt plus any crash retries / fallback)."""
    res: object                                 # RunResult of the FINAL attempt (success or last crash)
    crashed: bool = False                       # True iff rc!=0 after retries + fallback were exhausted
    cost: float = 0.0                           # total cost across every attempt in this logical leg
    attempts: list = field(default_factory=list)  # one diagnostics.leg_record per attempt
    reseeded: bool = False                      # the fresh-session fallback was used
    cause: str | None = None                    # short human crash cause when `crashed`


def _execute_leg(engine, prep, repo: Path, eng_dir: Path, *, prompt: str, resume: bool,
                 extra_allow: list, max_turns: int, leg_budget: float, audit: Path,
                 model: str | None = None):
    """Build + run EXACTLY ONE engine leg; return its ``RunResult``. The atomic unit of engine work
    (see the WAVE-2 SEAM note above — this is what the worker pool calls per shard).

    ``model`` routes THIS leg to a specific engine model (a pool shard's own model). It is forwarded to
    ``build_invocation`` ONLY when set, so the single-session ``drive`` path (which never supplies one)
    calls ``build_invocation`` with the EXACT same arguments as before — no behavior change, and an engine
    double whose ``build_invocation`` has no ``model`` kwarg stays compatible."""
    kwargs = dict(mode="autonomous", allow=extra_allow, max_turns=max_turns,
                  max_budget=leg_budget, resume=resume)
    if model is not None:
        kwargs["model"] = model
    inv = engine.build_invocation(prep, repo, prompt, **kwargs)
    return engine.run(prep, eng_dir, inv, mode="autonomous", audit=audit)


def _reseed_session(prep, eng_dir: Path) -> str | None:
    """Mint a FRESH `claude` session id for the resume-failure fallback and record it as the new resume
    anchor. Returns the new id (None if it can't be set). The engagement STATE is already on disk
    (ledgers / findings), so a brand-new session seeded by the continue-prompt rebuilds context — this
    is how we recover from an un-resumable session (the common `--resume` crash cause). Best-effort:
    the in-memory `prep.session_id` is authoritative for THIS process; persisting session.json just
    lets a later operator `--resume` target the working session."""
    try:
        new_id = str(uuid.uuid4())
        prep.session_id = new_id
    except Exception:
        return None
    try:
        sf = Path(eng_dir) / "runtime" / "session.json"
        sf.parent.mkdir(parents=True, exist_ok=True)
        sf.write_text(json.dumps({
            "session_id": new_id,
            "created": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "note": "reseeded by runloop after a resume-leg crash (un-resumable-session fallback)",
        }, indent=2) + "\n", encoding="utf-8")
    except Exception:
        pass
    return new_id


def _run_leg(engine, prep, repo: Path, eng_dir: Path, *, prompt: str, resume: bool,
             extra_allow: list, max_turns: int, audit: Path, engagement_id: str,
             cost_so_far: float, max_budget_usd: float, crash_retries: int,
             sleep, backoff: float, model: str | None = None) -> _LegOutcome:
    """Run ONE logical leg, BRANCHING ON ``rc`` so an engine CRASH is handled on its own path and can
    no longer masquerade as a no-progress stall:

      1. run the leg once (`_execute_leg`);
      2. while it CRASHED (rc!=0), RETRY up to ``crash_retries`` times with linear backoff — each
         attempt's cost still counts toward the global budget, and a retry is skipped once the
         remaining budget can no longer afford one;
      3. if a RESUME leg is still crashing after its retries, try ONE fresh `--session-id` leg seeded
         by the continue-prompt + the on-disk ledgers (state is persisted) — the un-resumable-session
         recovery;
      4. capture EVERY attempt's cause into ``attempts`` so a failing NON-final attempt is never lost.

    Returns a ``_LegOutcome``; ``crashed`` is True only when the leg could not be made to run."""
    out = _LegOutcome(res=None)

    def _remaining() -> float:
        return max_budget_usd - cost_so_far - out.cost

    def _attempt(p: str, r: bool, kind: str, attempt_no: int):
        leg_budget = max(_remaining(), BUDGET_FLOOR)
        res = _execute_leg(engine, prep, repo, eng_dir, prompt=p, resume=r,
                           extra_allow=extra_allow, max_turns=max_turns,
                           leg_budget=leg_budget, audit=audit, model=model)
        cost = _cost_of(res)
        out.cost += cost
        out.res = res
        out.attempts.append(diagnostics.leg_record(
            attempt=attempt_no, kind=kind, rc=getattr(res, "rc", 0), cost=cost,
            summary=getattr(res, "summary", None)))
        return res

    def _crashed(res) -> bool:
        return getattr(res, "rc", 0) not in (0, None)

    # attempt 1 — the leg as asked (resume or fresh initial)
    res = _attempt(prompt, resume, "resume" if resume else "initial", 1)

    # bounded retries with backoff, while it keeps crashing and the budget still affords one
    n = 0
    while _crashed(res) and n < crash_retries and _remaining() > BUDGET_FLOOR:
        n += 1
        try:
            sleep(backoff * n)
        except Exception:
            pass
        res = _attempt(prompt, resume, "retry", len(out.attempts) + 1)

    # resume-failure fallback: a RESUME leg still crashing → ONE fresh --session-id leg seeded by the
    # continue-prompt (state is already persisted on disk). Only for resume legs; a fresh initial leg
    # that crashes has no session to fall back from.
    if _crashed(res) and resume and _remaining() > BUDGET_FLOOR:
        if _reseed_session(prep, eng_dir) is not None:
            out.reseeded = True
            res = _attempt(continue_prompt(engagement_id, eng_dir), False,
                           "resume-fallback", len(out.attempts) + 1)

    out.crashed = _crashed(res)
    if out.crashed:
        out.cause = diagnostics.leg_cause(out.attempts[-1] if out.attempts else None)
    return out


def _decide_stop(repo: Path, eng_dir: Path, *, gate_verify, prev: "Snapshot | None",
                 cur: "Snapshot", stalls: int) -> tuple[str | None, int]:
    """The SHARED post-leg / post-wave completion+stop decision, factored out so the single-session
    ``drive`` and the concurrent ``drive_pool`` evaluate the completion contract IDENTICALLY — one copy,
    no divergence. Given the freshly-written engagement state (read via ``eng_dir``) plus this leg/wave's
    ``cur`` snapshot and the previous ``prev``, return ``(reason, stalls)``:

      * ``reason`` is a terminal stop reason (``DONE`` / ``BLOCKED_ON_APPROVAL`` / ``NO_PROGRESS``) or
        ``None`` to keep looping;
      * ``stalls`` is the updated consecutive-no-progress count the caller carries forward.

    It deliberately does NOT handle an engine crash (the caller branches on rc / crash BEFORE calling this)
    nor the hard ceilings (budget / max-invocations / wall-clock, checked before each new leg/wave). The
    order matches the original inline logic exactly: DONE first (gate clear AND nothing re-drivable — a gate
    that merely PASSES while categories are still `blocked` is NOT finished — AND no accepted FEEDER finding
    is still unchained, so the engagement can't reach report-ready with kill chains left uncomposed), then
    blocked-on-approval (deferrals exist and this leg/wave made no OTHER progress), then the two-strike
    no-progress breaker. The chain-pending set is BOUNDED (a feeder drops once chaining is attempted), and an
    engine that never runs the chainer simply makes no progress and is caught by the breaker below."""
    if (_gate_done(gate_verify, repo, eng_dir)
            and not redrivable_ids(read_ledger(eng_dir))
            and not chain_pending_ids(eng_dir)):
        return DONE, stalls
    progressed = made_progress(prev, cur)
    if pending_approvals_count(eng_dir) and not progressed:
        return BLOCKED_ON_APPROVAL, stalls
    stalls = stalls + 1 if not progressed else 0
    if stalls >= STALL_LIMIT:
        return NO_PROGRESS, stalls
    return None, stalls


def drive(engine, prep, repo: Path, eng_dir: Path, *, first_prompt: str, extra_allow: list,
          max_turns: int, max_budget_usd: float, first_resume: bool, audit: Path,
          engagement_id: str, gate_verify=None, emit=None, now=None, sleep=None) -> LoopResult:
    """Run the autonomous engagement to completion across resumed legs. Builds + runs the first
    invocation (honoring an operator ``first_resume``), then resumes the stable session with a
    fresh continue-prompt each time until the completion contract or a ceiling trips. Returns a
    ``LoopResult`` whose ``result`` reflects the WHOLE run (last leg's summary, cumulative cost,
    first start → last end) for the single post-run gate + diagnostics pass.

    Each leg is run through ``_run_leg``, which BRANCHES ON ``rc``: a CRASHED leg (rc!=0) is retried
    with backoff and (for a resume leg) recovered via a fresh-session fallback; only an unrecoverable
    crash ends the loop, with an honest ``engine-crash`` reason — never a masquerading ``no-progress``.
    ``sleep`` is injectable for tests (defaults to ``time.sleep`` for the retry backoff)."""
    gate_verify = gate_verify or gatemod.verify
    emit = emit or (lambda line: print(line))
    monotonic = now or time.monotonic
    sleep = sleep or time.sleep

    max_invocations = max(1, _env_int("REDSTRIKE_MAX_INVOCATIONS", DEFAULT_MAX_INVOCATIONS))
    max_wall = _env_float("REDSTRIKE_MAX_WALL_SECONDS", DEFAULT_MAX_WALL_SECONDS)
    crash_retries = max(0, _env_int("REDSTRIKE_CRASH_RETRIES", DEFAULT_CRASH_RETRIES))
    backoff = max(0.0, _env_float("REDSTRIKE_RETRY_BACKOFF_SECONDS", RETRY_BACKOFF_SECONDS))
    deadline = monotonic() + max_wall

    cumulative_cost = 0.0
    invocations = 0
    stalls = 0
    budgets: list[float] = []
    legs: list[dict] = []
    prev: Snapshot | None = None
    last_res = None
    started_first = ""
    reason = DONE
    crash_cause: str | None = None

    while True:
        # --- hard ceilings, checked before each NEW leg (the first leg always runs) ---
        if invocations > 0:
            remaining = max_budget_usd - cumulative_cost
            if remaining <= BUDGET_FLOOR:
                reason = BUDGET_EXHAUSTED
                break
            if invocations >= max_invocations:
                reason = MAX_INVOCATIONS
                break
            if monotonic() >= deadline:
                reason = WALL_CLOCK
                break

        # --- build + run one leg, branching on rc (crash recovery: retry + resume-fallback) ---
        remaining = max_budget_usd - cumulative_cost
        leg_budget = max(remaining, BUDGET_FLOOR)
        resume = first_resume if invocations == 0 else True
        if invocations == 0:
            prompt = first_prompt
        else:
            # deterministic plan pre-steps (#4): ensure the ledgers the continue-prompt (hunt_plan
            # ordering) + the completeness gates read are present/current BEFORE we build the resume
            # prompt — don't rely on the model to have run them. Best-effort; never fails the leg.
            try:
                run_plan_steps(repo, eng_dir, emit=emit)
            except Exception:
                pass
            prompt = continue_prompt(engagement_id, eng_dir)
        budgets.append(leg_budget)
        outcome = _run_leg(
            engine, prep, repo, eng_dir, prompt=prompt, resume=resume, extra_allow=extra_allow,
            max_turns=max_turns, audit=audit, engagement_id=engagement_id,
            cost_so_far=cumulative_cost, max_budget_usd=max_budget_usd,
            crash_retries=crash_retries, sleep=sleep, backoff=backoff,
        )
        invocations += 1
        res = outcome.res
        if not started_first:
            started_first = getattr(res, "started", "") or ""
        last_res = res
        cumulative_cost += outcome.cost
        legs.extend(outcome.attempts)

        # --- rc branch: an UNRECOVERABLE engine crash ends the loop honestly (never "no-progress") ---
        if outcome.crashed:
            reason = ENGINE_CRASH
            crash_cause = outcome.cause
            break

        # --- completion / stop decisions (the shared completion contract — see _decide_stop) ---
        # DONE only when the gate is clear AND no re-drivable work (pending OR blocked) remains. A gate
        # that PASSES while categories are still `blocked` (e.g. non-destructive detection an over-cautious
        # engine mislabeled "approval-gated") is NOT a finished engagement — keep resuming so the
        # continue-prompt drives those categories to actually run.
        cur = snapshot(eng_dir, res)
        stop, stalls = _decide_stop(repo, eng_dir, gate_verify=gate_verify, prev=prev, cur=cur, stalls=stalls)
        if stop is not None:
            reason = stop
            break

        prev = cur
        outstanding_now = len(redrivable_ids(read_ledger(eng_dir)))
        emit(ui.info(f"invocation {invocations} complete · {_plural(outstanding_now, 'category')} "
                     f"still outstanding · {_plural(cur.findings, 'finding')} so far · "
                     f"${cumulative_cost:.4f} of ${max_budget_usd:.2f} used · resuming…"))

    # --- audit close: reconcile the ledgers + materialize the report so the completeness gates can SEE the
    #     engagement before the single post-run gate runs (fix: the gates ran dark when reporting was
    #     skipped and a hunter swarm wrote findings directly). Best-effort; never alters the loop outcome. ---
    try:
        close_artifacts(repo, eng_dir, emit=emit)
    except Exception:
        pass

    # --- combine the legs into one whole-run result for the single gate + diagnostics pass ---
    pending_count = len(redrivable_ids(read_ledger(eng_dir)))
    n_approvals = pending_approvals_count(eng_dir)
    detail = loop_degraded_reason(
        reason, invocations=invocations, cumulative_cost=cumulative_cost,
        max_budget=max_budget_usd, pending_count=pending_count, pending_approvals=n_approvals,
        crash_cause=crash_cause,
    )

    final_summary = getattr(last_res, "summary", None)
    if final_summary is not None and not isinstance(final_summary, str):
        try:
            final_summary.cost_usd = cumulative_cost   # the whole-run cost, not just the last leg
        except Exception:
            pass
    combined = RunResult(
        rc=getattr(last_res, "rc", 0),
        summary=(final_summary if final_summary is not None else ""),
        started=started_first or getattr(last_res, "started", "") or "",
        ended=getattr(last_res, "ended", "") or _dt.datetime.now(_dt.timezone.utc).isoformat(),
    )

    # --- final whole-run summary line ---
    emit(ui.rule("autonomous loop complete"))
    line = (f"{_plural(invocations, 'invocation')} · ${cumulative_cost:.4f} total · "
            f"{_plural(pending_count, 'category')} still outstanding · {reason}")
    emit((ui.ok if reason == DONE else ui.warn)(line))
    if detail:
        emit(ui.warn(detail))

    return LoopResult(
        result=combined,
        invocations=invocations,
        cumulative_cost=cumulative_cost,
        reason=reason,
        stop_detail=detail,
        budgets=budgets,
        pending_count=pending_count,
        legs=legs,
    )


# --- Wave-2 (2b) multi-process worker-pool scheduler --------------------------
# `drive` resumes ONE session leg-after-leg; `drive_pool` fans several `claude -p` legs out AT ONCE — one
# shard per `--shard-models` entry, each on its own model — and joins them into a WAVE, then runs the SAME
# completion contract (`_decide_stop`) on the joined on-disk state, wave after wave, until it (or a ceiling)
# trips. See the WAVE-2 SEAM note above the single-leg primitives it composes.

def shard_model_list(shard_models) -> list[str]:
    """Normalize a ``--shard-models`` spec (a list/tuple, or a comma string) into a clean list of model ids,
    trimming whitespace and dropping blanks. The CLI dispatches on the LENGTH: ``> 1`` entries ⇒ the
    concurrent pool (``drive_pool``), otherwise the single-session ``drive`` — so no / one shard-model is
    byte-for-byte the legacy path."""
    if isinstance(shard_models, (list, tuple)):
        parts = [str(x).strip() for x in shard_models]
    else:
        parts = [p.strip() for p in str(shard_models or "").split(",")]
    return [p for p in parts if p]


def _tool_calls_of(res) -> int:
    """Per-leg tool-call count from a RunResult's RunSummary (0 when absent/garbage) — summed across a
    wave's shards to feed the no-progress breaker the same signal ``snapshot`` gives the single path."""
    s = getattr(res, "summary", None)
    try:
        return int(getattr(s, "tool_calls", 0) or 0)
    except (TypeError, ValueError):
        return 0


@dataclass
class _ShardResult:
    """One shard's outcome within a wave: its index, the model it ran on, the ``_LegOutcome`` it produced
    (or None if the worker itself raised before producing one), and any worker-level exception captured so a
    crashing shard can never take down the pool."""
    idx: int
    model: str | None
    outcome: object = None            # _LegOutcome, or None when the worker raised before producing one
    error: BaseException | None = None

    @property
    def crashed(self) -> bool:
        """A shard crashed when its worker raised, or its leg could not be made to run (rc!=0 after retries +
        fallback). A shard that produced a clean final attempt did NOT crash."""
        if self.error is not None or self.outcome is None:
            return True
        return bool(getattr(self.outcome, "crashed", False))

    @property
    def cost(self) -> float:
        return float(getattr(self.outcome, "cost", 0.0) or 0.0) if self.outcome is not None else 0.0


def drive_pool(engine, prep, repo: Path, eng_dir: Path, *, first_prompt: str, extra_allow: list,
               max_turns: int, max_budget_usd: float, first_resume: bool, audit: Path,
               engagement_id: str, shard_models, gate_verify=None, emit=None, now=None, sleep=None,
               executor_factory=None) -> LoopResult:
    """Run the autonomous engagement to completion as CONCURRENT per-model SHARDS — the Wave-2 (2b)
    multi-process worker pool. Where ``drive`` resumes ONE session leg after leg, ``drive_pool`` fans several
    ``claude -p`` legs out at once (one per ``shard_models`` entry, each on its own model), joins them into a
    WAVE, then runs the SAME post-wave completion contract as ``drive`` (``_decide_stop``) on the joined
    on-disk state — wave after wave until that contract or a ceiling trips. Returns a ``LoopResult`` of the
    exact shape ``drive`` returns, for the one post-run gate + diagnostics pass.

    CONCURRENCY MODEL
      Each shard is an independent engine leg run on a thread (``concurrent.futures.ThreadPoolExecutor`` by
      default; injectable via ``executor_factory`` for tests). Threads are the right fit — NOT processes —
      because every leg BLOCKS on a ``claude -p`` SUBPROCESS: the GIL is released during that wait, so N
      threads give true process-level parallelism with none of ``ProcessPoolExecutor``'s pickling/spawn
      overhead. Each shard reuses ``_run_leg``, so it inherits the same rc-branching + bounded crash-retry +
      resume-fallback a single leg gets.

    CRASH ISOLATION
      Every shard runs inside a try/except in its worker, so a shard that raises or whose leg can't be made
      to run is recorded as a crashed shard while the OTHERS are unaffected. A WAVE is an ``engine-crash``
      only when EVERY shard crashed (genuinely no progress) — a single crashed shard whose work the others
      covered is NOT a whole-run failure (the module's honest-reason discipline).

    PER-SHARD SESSION
      Concurrent shards CANNOT share one ``--resume`` session or one ``prep.session_id`` (and
      ``_reseed_session`` MUTATES ``prep.session_id``), so each shard gets a SHALLOW-CLONED ``prep`` with its
      OWN fresh session id and runs as a FRESH (``resume=False``) leg seeded by the wave prompt. The
      engagement STATE lives on disk (coverage/surface ledgers + findings), so a fresh session rebuilds
      context from the continue-prompt and shards never stomp each other's in-session state. (Because shards
      are fresh, ``_run_leg``'s resume-fallback never fires for them; bounded crash retries still do.)

    GLOBAL BUDGET SAFETY (the correctness-critical choice)
      The budget is GLOBAL. Rather than share a mutable budget counter across threads (which would need a
      lock and still risk double-counting), before each wave the REMAINING global budget is PARTITIONED
      evenly across the N shards — each shard's slice becomes its OWN ``max_budget_usd`` — so the shards
      cannot, in aggregate, exceed what is left. Actual costs are summed only AFTER the wave joins, with no
      cross-thread mutation. (Edge: a slice is floored at ``BUDGET_FLOOR`` so every shard has a usable
      budget; at the very tail this can overshoot the global cap by at most ``N * BUDGET_FLOOR`` — the same
      floor overshoot ``drive`` already allows on its last leg — after which the pre-wave ceiling check
      stops the run.)

    LEDGER CONCURRENCY
      Shards mutate the SHARED ledgers ONLY through the scripts (``coverage.py`` / ``surface.py`` /
      ``dedup.py``), each of which serializes its read-modify-write with a cross-process advisory file lock +
      atomic rename, so concurrent marks/closes/merges survive. The deterministic plan pre-steps
      (``run_plan_steps``) run ONCE per wave BEFORE fan-out, never concurrently per shard. Each shard streams
      to its OWN audit file so the per-process JSONL streams never interleave.

    DIAGNOSTICS
      Every shard's every attempt is aggregated into ``LoopResult.legs`` (each tagged with its shard index +
      model), so a crashed non-final shard's cause survives for the per-leg diagnostics overlay.

    ``sleep`` / ``now`` / ``executor_factory`` are injectable for tests."""
    gate_verify = gate_verify or gatemod.verify
    emit = emit or (lambda line: print(line))
    monotonic = now or time.monotonic
    sleep = sleep or time.sleep
    executor_factory = executor_factory or concurrent.futures.ThreadPoolExecutor

    models = shard_model_list(shard_models) or [None]
    n = len(models)

    max_invocations = max(1, _env_int("REDSTRIKE_MAX_INVOCATIONS", DEFAULT_MAX_INVOCATIONS))
    max_wall = _env_float("REDSTRIKE_MAX_WALL_SECONDS", DEFAULT_MAX_WALL_SECONDS)
    crash_retries = max(0, _env_int("REDSTRIKE_CRASH_RETRIES", DEFAULT_CRASH_RETRIES))
    backoff = max(0.0, _env_float("REDSTRIKE_RETRY_BACKOFF_SECONDS", RETRY_BACKOFF_SECONDS))
    deadline = monotonic() + max_wall

    cumulative_cost = 0.0
    waves = 0
    stalls = 0
    budgets: list[float] = []     # the per-shard slice handed to each shard, one entry per wave
    legs: list[dict] = []
    prev: Snapshot | None = None
    last_res = None
    started_first = ""
    reason = DONE
    crash_cause: str | None = None

    def _shard_audit(idx: int) -> Path:
        """A per-shard audit path so N concurrent `claude -p` streams never interleave into one JSONL."""
        try:
            a = Path(audit)
            return a.with_name(f"{a.stem}.shard-{idx}{a.suffix}")
        except Exception:
            return Path(audit)

    while True:
        # --- hard ceilings, checked before each NEW wave (the first wave always runs) ---
        if waves > 0:
            remaining = max_budget_usd - cumulative_cost
            if remaining <= BUDGET_FLOOR:
                reason = BUDGET_EXHAUSTED
                break
            if waves >= max_invocations:
                reason = MAX_INVOCATIONS
                break
            if monotonic() >= deadline:
                reason = WALL_CLOCK
                break

        # --- wave prompt: the launch prompt only for a FRESH first wave; otherwise the continue-prompt,
        #     with the deterministic plan pre-steps run ONCE here (before fan-out), never per shard. ---
        if waves > 0 or first_resume:
            try:
                run_plan_steps(repo, eng_dir, emit=emit)
            except Exception:
                pass
            wave_prompt = continue_prompt(engagement_id, eng_dir)
        else:
            wave_prompt = first_prompt

        # --- partition the REMAINING global budget evenly across the shards (per-shard slice) ---
        remaining = max_budget_usd - cumulative_cost
        shard_budget = max(remaining / n, BUDGET_FLOOR)
        budgets.append(shard_budget)

        # --- one worker per shard: its OWN cloned prep + fresh session id, run as a fresh leg, fully
        #     isolated so one shard raising/crashing can never kill the others or the pool. ---
        def _run_shard(idx: int, model, _prompt=wave_prompt, _budget=shard_budget) -> _ShardResult:
            shard_prep = copy.copy(prep)
            try:
                shard_prep.session_id = str(uuid.uuid4())
            except Exception:
                pass
            try:
                outcome = _run_leg(
                    engine, shard_prep, repo, eng_dir, prompt=_prompt, resume=False,
                    extra_allow=extra_allow, max_turns=max_turns, audit=_shard_audit(idx),
                    engagement_id=engagement_id, cost_so_far=0.0, max_budget_usd=_budget,
                    crash_retries=crash_retries, sleep=sleep, backoff=backoff, model=model,
                )
                return _ShardResult(idx=idx, model=model, outcome=outcome)
            except BaseException as e:   # crash isolation: a shard can NEVER take down the pool
                return _ShardResult(idx=idx, model=model, error=e)

        shard_results: list[_ShardResult] = []
        with executor_factory(max_workers=n) as ex:
            futs = [ex.submit(_run_shard, i, m) for i, m in enumerate(models)]
            for fut in concurrent.futures.as_completed(futs):
                try:
                    shard_results.append(fut.result())
                except BaseException as e:   # belt-and-suspenders — _run_shard already traps its own
                    shard_results.append(_ShardResult(idx=-1, model=None, error=e))
        shard_results.sort(key=lambda s: s.idx)
        waves += 1

        # --- join: aggregate cost + every attempt (tagged by shard/model) + a representative final res ---
        wave_cost = 0.0
        wave_tool_calls = 0
        wave_last_res = None       # last res from ANY shard (crashed or not)
        wave_last_ok_res = None    # last res from a NON-crashed shard — preferred for combined.rc
        for s in shard_results:
            wave_cost += s.cost
            oc = s.outcome
            if oc is None:
                continue
            for a in getattr(oc, "attempts", None) or []:
                rec = dict(a)
                rec["shard"], rec["model"] = s.idx, s.model
                legs.append(rec)
            res = getattr(oc, "res", None)
            if res is not None:
                wave_last_res = res
                if not s.crashed:
                    wave_last_ok_res = res
                if not started_first:
                    started_first = getattr(res, "started", "") or ""
                wave_tool_calls += _tool_calls_of(res)
        cumulative_cost += wave_cost
        rep = wave_last_ok_res or wave_last_res
        if rep is not None:
            last_res = rep

        # --- rc branch: a wave is an ENGINE crash ONLY when EVERY shard crashed (honest-reason discipline:
        #     a single crashed shard whose work others covered is not a whole-run failure) ---
        if shard_results and all(s.crashed for s in shard_results):
            reason = ENGINE_CRASH
            with_cause = next((s for s in shard_results
                               if s.outcome is not None and getattr(s.outcome, "cause", None)), None)
            if with_cause is not None:
                crash_cause = with_cause.outcome.cause
            else:
                err = next((s.error for s in shard_results if s.error is not None), None)
                crash_cause = f"{type(err).__name__}: {err}" if err is not None else "all shards crashed"
            break

        # --- completion / stop decisions (the SAME shared contract as drive — see _decide_stop) ---
        cur = Snapshot(pending=pending_ids(read_ledger(eng_dir)),
                       findings=_findings_total(eng_dir), tool_calls=wave_tool_calls)
        stop, stalls = _decide_stop(repo, eng_dir, gate_verify=gate_verify, prev=prev, cur=cur, stalls=stalls)
        if stop is not None:
            reason = stop
            break

        prev = cur
        outstanding_now = len(redrivable_ids(read_ledger(eng_dir)))
        emit(ui.info(f"wave {waves} complete ({_plural(n, 'shard')}) · "
                     f"{_plural(outstanding_now, 'category')} still outstanding · "
                     f"{_plural(cur.findings, 'finding')} so far · ${cumulative_cost:.4f} of "
                     f"${max_budget_usd:.2f} used · resuming…"))

    # --- audit close: reconcile ledgers + materialize the report so the completeness gates can SEE the
    #     engagement before the single post-run gate runs. Best-effort; never alters the outcome. ---
    try:
        close_artifacts(repo, eng_dir, emit=emit)
    except Exception:
        pass

    # --- combine the waves into one whole-run result for the single gate + diagnostics pass ---
    pending_count = len(redrivable_ids(read_ledger(eng_dir)))
    n_approvals = pending_approvals_count(eng_dir)
    detail = loop_degraded_reason(
        reason, invocations=waves, cumulative_cost=cumulative_cost, max_budget=max_budget_usd,
        pending_count=pending_count, pending_approvals=n_approvals, crash_cause=crash_cause,
    )

    final_summary = getattr(last_res, "summary", None)
    if final_summary is not None and not isinstance(final_summary, str):
        try:
            final_summary.cost_usd = cumulative_cost   # the whole-run cost, not just the last shard
        except Exception:
            pass
    combined = RunResult(
        rc=getattr(last_res, "rc", 0),
        summary=(final_summary if final_summary is not None else ""),
        started=started_first or getattr(last_res, "started", "") or "",
        ended=getattr(last_res, "ended", "") or _dt.datetime.now(_dt.timezone.utc).isoformat(),
    )

    # --- final whole-run summary line ---
    emit(ui.rule("autonomous pool complete"))
    line = (f"{_plural(waves, 'wave')} × {_plural(n, 'shard')} · ${cumulative_cost:.4f} total · "
            f"{_plural(pending_count, 'category')} still outstanding · {reason}")
    emit((ui.ok if reason == DONE else ui.warn)(line))
    if detail:
        emit(ui.warn(detail))

    return LoopResult(
        result=combined,
        invocations=waves,
        cumulative_cost=cumulative_cost,
        reason=reason,
        stop_detail=detail,
        budgets=budgets,
        pending_count=pending_count,
        legs=legs,
    )
