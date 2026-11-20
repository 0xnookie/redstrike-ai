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
        f"repeat completed work: consult coverage_ledger.json and skip every category already done "
        f"('attempted' with findings, 'skipped', or 'n/a')."
    )
    if not outstanding:
        return (
            head + " No specific categories were parseable as outstanding — finish any remaining "
            "coverage per coverage_ledger.json (run non-destructive detection for any category still "
            "'pending' or 'blocked' — detection and benign PoCs are NOT gated), then re-converge, run "
            "the recall-audit, compose attack chains over accepted findings, and write the report. "
            "Only a genuine exploitation / destructive / RCE command defers for operator approval; "
            "when one does, record it, skip that one step, and CONTINUE the rest — never halt the "
            "whole run at a gate."
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
        "subagent, then mark coverage_ledger.json with scripts/coverage.py --mark. Vulnerability "
        "DETECTION and benign PoCs are NON-destructive and are NOT gated — run them now; a category "
        "previously left 'blocked' as approval-gated must have its non-destructive detection run. "
        "Only a genuine exploitation / destructive / RCE command defers at the scope gate: when one "
        "does, it is queued in runtime/approvals_pending.json for the operator — record it, skip "
        "that one step, and CONTINUE the rest; never halt the whole run at a gate. When no "
        "categories remain outstanding, re-converge, run the recall-audit, compose attack chains "
        "over accepted findings, and write the report."
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
# WAVE-2 SEAM. A later wave promotes `drive` from a single-session resumer into a worker-pool
# scheduler of N parallel legs. `_execute_leg` is the ATOMIC unit of engine work — the per-shard call
# a pool fans out; `_run_leg` wraps it with the rc-branching / bounded-retry / resume-fallback a pool
# can reuse per shard. Keep these two factored OUT of `drive` so the pool can call the single-leg path
# directly; do not inline them back. `drive` composes `_run_leg` across resumed legs (the single
# session) — the pool composes it across shards.

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
                 extra_allow: list, max_turns: int, leg_budget: float, audit: Path):
    """Build + run EXACTLY ONE engine leg; return its ``RunResult``. The atomic unit of engine work
    (see the WAVE-2 SEAM note above — this is what a worker pool calls per shard)."""
    inv = engine.build_invocation(
        prep, repo, prompt, mode="autonomous", allow=extra_allow,
        max_turns=max_turns, max_budget=leg_budget, resume=resume,
    )
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
             sleep, backoff: float) -> _LegOutcome:
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
                           leg_budget=leg_budget, audit=audit)
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
        prompt = first_prompt if invocations == 0 else continue_prompt(engagement_id, eng_dir)
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

        # --- completion / stop decisions ---
        # DONE only when the gate is clear AND no re-drivable work (pending OR blocked) remains. A
        # gate that PASSES while categories are still `blocked` (e.g. non-destructive detection an
        # over-cautious engine mislabeled "approval-gated") is NOT a finished engagement — keep
        # resuming so the continue-prompt drives those categories to actually run.
        gate_clear = _gate_done(gate_verify, repo, eng_dir)
        if gate_clear and not redrivable_ids(read_ledger(eng_dir)):
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
