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

import datetime as _dt
import json
import os
import time
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

# --- ceilings / thresholds ---------------------------------------------------
DEFAULT_MAX_INVOCATIONS = 10            # env REDSTRIKE_MAX_INVOCATIONS
DEFAULT_MAX_WALL_SECONDS = 24 * 3600    # env REDSTRIKE_MAX_WALL_SECONDS (generous backstop)
BUDGET_FLOOR = 0.25                     # stop once remaining global budget <= this
NO_PROGRESS_TOOLCALLS = 1              # "~zero new tool calls" for a leg == did nothing
STALL_LIMIT = 2                        # consecutive no-progress legs that trip the breaker


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
    coverage gate blocks on and the no-progress breaker compares across legs."""
    if not isinstance(ledger, dict):
        return frozenset()
    out = set()
    for c in ledger.get("categories") or []:
        if isinstance(c, dict) and str(c.get("status", "")).lower() == "pending":
            cid = c.get("id") or c.get("name")
            if cid:
                out.add(str(cid))
    return frozenset(out)


def outstanding_categories(ledger: dict | None) -> list[dict]:
    """Categories the continue-prompt should name: still `pending`, OR `attempted` with zero
    findings and an escalation ladder that is not obviously exhausted (so an empty-but-signalled
    surface gets another, deeper pass)."""
    if not isinstance(ledger, dict):
        return []
    out: list[dict] = []
    for c in ledger.get("categories") or []:
        if not isinstance(c, dict):
            continue
        st = str(c.get("status", "")).lower()
        if st == "pending":
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


# --- continue-prompt (pure) --------------------------------------------------
def continue_prompt(engagement_id: str, eng_dir: Path, *, max_list: int = 25) -> str:
    """The resume prompt for leg 2+: name exactly what's left from the coverage ledger and tell
    the engine to continue the orchestrator pipeline on those, then re-converge / recall-audit /
    chain / report — without repeating completed work. Falls back to a generic continue when the
    ledger can't be read."""
    ledger = read_ledger(eng_dir)
    outstanding = outstanding_categories(ledger)
    head = (
        f"Continue Redstrike engagement '{engagement_id}' from where the previous invocation "
        f"stopped (it hit its per-invocation turn cap, not the end of the work). Authorization "
        f"and scope are already recorded (RoE appended) — §0 is SATISFIED, do not re-ask. Do NOT "
        f"repeat completed work: consult coverage_ledger.json and skip every category already "
        f"'attempted'/'skipped'/'n/a'."
    )
    if not outstanding:
        return (
            head + " No specific categories were parseable as outstanding — finish any remaining "
            "coverage per coverage_ledger.json, then re-converge, run the recall-audit, compose "
            "attack chains over accepted findings, and write the report. Honor the active scope "
            "gate and STOP/defer at any approval-gated or destructive step."
        )
    shown = outstanding[:max_list]
    bullets = []
    for c in shown:
        cid = c.get("id") or c.get("name") or "?"
        st = str(c.get("status", "")).lower()
        tag = "pending" if st == "pending" else "attempted, 0 findings — escalate further"
        bullets.append(f"- {cid} ({tag})")
    more = len(outstanding) - len(shown)
    if more > 0:
        bullets.append(f"- …and {more} more still outstanding in coverage_ledger.json")
    return (
        head
        + " The following vulnerability categories are still OUTSTANDING:\n"
        + "\n".join(bullets)
        + "\nInvoke the redstrike orchestrator skill and run the orchestrator pipeline on exactly "
        "these: for each, its context feeder (if any) → executor → the independent verify "
        "subagent, then mark coverage_ledger.json with scripts/coverage.py --mark. When no "
        "outstanding categories remain, re-converge, run the recall-audit, compose attack chains "
        "over accepted findings, and write the report. Honor the active scope gate and STOP/defer "
        "at any approval-gated or destructive step instead of proceeding."
    )


# --- diagnostics overlay (pure) ----------------------------------------------
def loop_degraded_reason(reason: str, *, invocations: int, cumulative_cost: float,
                         max_budget: float, pending_count: int, pending_approvals: int) -> str | None:
    """A human, honest one-liner for why the WHOLE looped run ended (None when it completed)."""
    if reason == DONE:
        return None
    if reason == BUDGET_EXHAUSTED:
        return (f"stopped after {invocations} invocation(s): the global budget (${max_budget:.2f}) "
                f"was exhausted (${cumulative_cost:.2f} spent) with {pending_count} category/ies "
                f"still pending — coverage is partial, relaunch with a higher --max-budget-usd")
    if reason == MAX_INVOCATIONS:
        return (f"stopped after the max of {invocations} resume invocation(s) with {pending_count} "
                f"category/ies still pending — coverage is partial (raise REDSTRIKE_MAX_INVOCATIONS "
                f"to allow more legs)")
    if reason == WALL_CLOCK:
        return (f"stopped after {invocations} invocation(s): the wall-clock ceiling was hit with "
                f"{pending_count} category/ies still pending — coverage is partial")
    if reason == NO_PROGRESS:
        return (f"stopped after {invocations} invocation(s): two consecutive resumes made no "
                f"progress ({pending_count} category/ies still pending) — the run is stuck")
    if reason == BLOCKED_ON_APPROVAL:
        return (f"run paused after {invocations} invocation(s): {pending_approvals} action(s) await "
                f"operator approval and nothing else advanced — approve in the console, then "
                f"relaunch with --resume")
    return None


def annotate_record(record: dict, loop: "LoopResult") -> dict:
    """Overlay the loop's whole-run stop reason onto a diagnostics record so the OUTCOME is honest:
    a budget-truncated / max-invocation / stuck / blocked run is degraded (coverage partial), not
    'clean'. Never overwrites a real finding delivery (produced-findings) and leaves a cleanly
    completed run (reason==done) exactly as classify_outcome decided."""
    if loop.reason == DONE:
        return record
    if record.get("outcome") == diagnostics.PRODUCED:
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


def drive(engine, prep, repo: Path, eng_dir: Path, *, first_prompt: str, extra_allow: list,
          max_turns: int, max_budget_usd: float, first_resume: bool, audit: Path,
          engagement_id: str, gate_verify=None, emit=None, now=None) -> LoopResult:
    """Run the autonomous engagement to completion across resumed legs. Builds + runs the first
    invocation (honoring an operator ``first_resume``), then resumes the stable session with a
    fresh continue-prompt each time until the completion contract or a ceiling trips. Returns a
    ``LoopResult`` whose ``result`` reflects the WHOLE run (last leg's summary, cumulative cost,
    first start → last end) for the single post-run gate + diagnostics pass."""
    gate_verify = gate_verify or gatemod.verify
    emit = emit or (lambda line: print(line))
    monotonic = now or time.monotonic

    max_invocations = max(1, _env_int("REDSTRIKE_MAX_INVOCATIONS", DEFAULT_MAX_INVOCATIONS))
    max_wall = _env_float("REDSTRIKE_MAX_WALL_SECONDS", DEFAULT_MAX_WALL_SECONDS)
    deadline = monotonic() + max_wall

    cumulative_cost = 0.0
    invocations = 0
    stalls = 0
    budgets: list[float] = []
    prev: Snapshot | None = None
    last_res = None
    started_first = ""
    reason = DONE

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

        # --- build + run one leg ---
        remaining = max_budget_usd - cumulative_cost
        leg_budget = max(remaining, BUDGET_FLOOR)
        resume = first_resume if invocations == 0 else True
        prompt = first_prompt if invocations == 0 else continue_prompt(engagement_id, eng_dir)
        inv = engine.build_invocation(
            prep, repo, prompt, mode="autonomous", allow=extra_allow,
            max_turns=max_turns, max_budget=leg_budget, resume=resume,
        )
        budgets.append(leg_budget)
        res = engine.run(prep, eng_dir, inv, mode="autonomous", audit=audit)
        invocations += 1
        if not started_first:
            started_first = getattr(res, "started", "") or ""
        last_res = res
        cumulative_cost += _cost_of(res)

        # --- completion / stop decisions ---
        if _gate_done(gate_verify, repo, eng_dir):
            reason = DONE
            break

        cur = snapshot(eng_dir, res)
        progressed = made_progress(prev, cur)
        n_approvals = pending_approvals_count(eng_dir)
        if n_approvals and not progressed:
            reason = BLOCKED_ON_APPROVAL
            break
        stalls = stalls + 1 if not progressed else 0
        if stalls >= STALL_LIMIT:
            reason = NO_PROGRESS
            break

        prev = cur
        pend = len(cur.pending)
        emit(ui.info(f"invocation {invocations} complete · {_plural(pend, 'category')} still "
                     f"pending · {_plural(cur.findings, 'finding')} so far · ${cumulative_cost:.4f} "
                     f"of ${max_budget_usd:.2f} used · resuming…"))

    # --- combine the legs into one whole-run result for the single gate + diagnostics pass ---
    pending_count = len(pending_ids(read_ledger(eng_dir)))
    n_approvals = pending_approvals_count(eng_dir)
    detail = loop_degraded_reason(
        reason, invocations=invocations, cumulative_cost=cumulative_cost,
        max_budget=max_budget_usd, pending_count=pending_count, pending_approvals=n_approvals,
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
            f"{_plural(pending_count, 'category')} still pending · {reason}")
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
    )
