import concurrent.futures
import io
import json
import os
import pathlib
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager, redirect_stdout
from types import SimpleNamespace


@contextmanager
def _set_env(name, value):
    """Temporarily set (or, if value is None, unset) an env var; restore it afterward."""
    old = os.environ.get(name)
    if value is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = str(value)
    try:
        yield
    finally:
        if old is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = old

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # cli/

from redstrike_cli import autorun, diagnostics, engagement, engines, runloop  # noqa: E402
from redstrike_cli.__main__ import main  # noqa: E402


# --- scripted fakes (no real `claude`) ---------------------------------------
class _Leg:
    """One scripted engine invocation: its cost, the tool calls it made, its rc, and an optional
    side effect that mutates the engagement dir (write the ledger / findings / approvals)."""

    def __init__(self, cost=0.0, tool_calls=0, rc=0, side_effect=None):
        self.cost = cost
        self.tool_calls = tool_calls
        self.rc = rc
        self.side_effect = side_effect


class _FakeEngine:
    def __init__(self, legs):
        self.legs = list(legs)
        self.budgets = []
        self.prompts = []
        self.resumes = []
        self.run_count = 0

    def build_invocation(self, prep, repo, prompt, *, mode="autonomous", allow=None,
                         max_turns=200, max_budget=20.0, resume=False):
        self.budgets.append(max_budget)
        self.prompts.append(prompt)
        self.resumes.append(resume)
        return SimpleNamespace(argv=["fake"], allowed=[])

    def run(self, prep, eng_dir, inv, *, mode="autonomous", audit=None):
        leg = self.legs[self.run_count] if self.run_count < len(self.legs) else self.legs[-1]
        self.run_count += 1
        if leg.side_effect:
            leg.side_effect(pathlib.Path(eng_dir))
        s = autorun.RunSummary(cost_usd=leg.cost, tool_calls=leg.tool_calls)
        return engines.RunResult(rc=leg.rc, summary=s, started="2026-01-01T00:00:00Z",
                                 ended="2026-01-01T00:05:00Z")


def _gate(values):
    """A gate.verify stand-in that returns the scripted ints in order, repeating the last."""
    seq = list(values)
    state = {"i": 0}

    def _g(repo, eng):
        i = min(state["i"], len(seq) - 1)
        state["i"] += 1
        return seq[i]
    return _g


def _clock(values):
    seq = list(values)
    state = {"i": 0}

    def _c():
        i = min(state["i"], len(seq) - 1)
        state["i"] += 1
        return seq[i]
    return _c


def _prep():
    return SimpleNamespace(engagement_id="acme-eng", session_id="sess-1", scope={})


def _write_ledger(eng_dir, cats):
    (pathlib.Path(eng_dir) / "coverage_ledger.json").write_text(
        json.dumps({"categories": cats}), encoding="utf-8")


def _silent(_line):
    return None


class _Eng:
    """A temp engagement dir with runtime/ ready."""

    def __enter__(self):
        self._td = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self._td.name)
        (self.dir / "runtime").mkdir()
        return self.dir

    def __exit__(self, *a):
        self._td.cleanup()


def _drive(engine, eng_dir, *, gate, max_budget_usd=100.0, first_resume=False, now=None,
           prep=None):
    return runloop.drive(
        engine, prep or _prep(), pathlib.Path("/repo"), eng_dir,
        first_prompt="GO", extra_allow=[], max_turns=50, max_budget_usd=max_budget_usd,
        first_resume=first_resume, audit=eng_dir / "runtime" / "autorun.jsonl",
        engagement_id="acme-eng", gate_verify=gate, emit=_silent, now=now,
        sleep=lambda _s: None,   # no real backoff sleeps in tests
    )


# --- the loop behaviors -------------------------------------------------------
class TestDriveCompletion(unittest.TestCase):
    def test_resumes_until_gate_clear(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "pending", "findings_count": 0},
                                {"id": "sqli", "status": "pending", "findings_count": 0}])

            def done(e):
                _write_ledger(e, [{"id": "xss", "status": "attempted", "findings_count": 1},
                                  {"id": "sqli", "status": "attempted", "findings_count": 0}])

            legs = [_Leg(cost=0.1, tool_calls=5), _Leg(cost=0.1, tool_calls=5),
                    _Leg(cost=0.1, tool_calls=5, side_effect=done)]
            engine = _FakeEngine(legs)
            res = _drive(engine, eng, gate=_gate([2, 2, 0]), first_resume=False)

            self.assertEqual(res.reason, runloop.DONE)
            self.assertEqual(res.invocations, 3)
            # first leg honors the operator resume flag (False here); every later leg resumes
            self.assertFalse(engine.resumes[0])
            self.assertTrue(all(engine.resumes[1:]))
            # first prompt is the launch prompt; resume legs get a continue-prompt
            self.assertEqual(engine.prompts[0], "GO")
            self.assertIn("Continue Redstrike engagement", engine.prompts[1])
            # combined result carries first→last bounds + cumulative cost on the summary
            self.assertEqual(res.result.started, "2026-01-01T00:00:00Z")
            self.assertAlmostEqual(res.result.summary.cost_usd, 0.3)

    def test_first_resume_flag_is_honored(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "pending"}])
            engine = _FakeEngine([_Leg(cost=0.1, tool_calls=5, side_effect=lambda e: _write_ledger(
                e, [{"id": "xss", "status": "attempted", "findings_count": 1}]))])
            res = _drive(engine, eng, gate=_gate([0]), first_resume=True)
            self.assertEqual(res.reason, runloop.DONE)
            self.assertEqual(res.invocations, 1)
            self.assertTrue(engine.resumes[0])  # operator --resume carried into the first leg


class TestDriveCeilings(unittest.TestCase):
    def test_global_budget_respected(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "pending"}])  # never clears
            engine = _FakeEngine([_Leg(cost=7.0, tool_calls=5)])      # fallback repeats the leg
            res = _drive(engine, eng, gate=_gate([2]), max_budget_usd=20.0)

            self.assertEqual(res.reason, runloop.BUDGET_EXHAUSTED)
            self.assertEqual(res.invocations, 3)
            # each leg is capped at the REMAINING global budget, never more than the total
            self.assertEqual(engine.budgets, [20.0, 13.0, 6.0])
            self.assertTrue(all(b <= 20.0 for b in engine.budgets))
            self.assertAlmostEqual(res.cumulative_cost, 21.0)

    def test_max_invocations_cap(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "pending"}])
            engine = _FakeEngine([_Leg(cost=0.1, tool_calls=5)])
            old = os.environ.get("REDSTRIKE_MAX_INVOCATIONS")
            os.environ["REDSTRIKE_MAX_INVOCATIONS"] = "3"
            try:
                res = _drive(engine, eng, gate=_gate([2]), max_budget_usd=1000.0)
            finally:
                if old is None:
                    os.environ.pop("REDSTRIKE_MAX_INVOCATIONS", None)
                else:
                    os.environ["REDSTRIKE_MAX_INVOCATIONS"] = old
            self.assertEqual(res.reason, runloop.MAX_INVOCATIONS)
            self.assertEqual(res.invocations, 3)

    def test_wall_clock_backstop(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "pending"}])
            engine = _FakeEngine([_Leg(cost=0.1, tool_calls=5)])
            old = os.environ.get("REDSTRIKE_MAX_WALL_SECONDS")
            os.environ["REDSTRIKE_MAX_WALL_SECONDS"] = "10"
            try:
                # clock: start=0 (deadline=10), then 100 at the next ceiling check
                res = _drive(engine, eng, gate=_gate([2]), max_budget_usd=1000.0,
                             now=_clock([0.0, 100.0]))
            finally:
                if old is None:
                    os.environ.pop("REDSTRIKE_MAX_WALL_SECONDS", None)
                else:
                    os.environ["REDSTRIKE_MAX_WALL_SECONDS"] = old
            self.assertEqual(res.reason, runloop.WALL_CLOCK)
            self.assertEqual(res.invocations, 1)


class TestDriveBreakers(unittest.TestCase):
    def test_no_progress_breaker(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "pending"}])  # constant; no findings
            engine = _FakeEngine([_Leg(cost=0.1, tool_calls=0)])      # zero tool work every leg
            res = _drive(engine, eng, gate=_gate([2]), max_budget_usd=1000.0)
            self.assertEqual(res.reason, runloop.NO_PROGRESS)
            self.assertEqual(res.invocations, 2)  # two consecutive stalls

    def test_blocked_on_approval(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "pending"}])

            def defer(e):
                (pathlib.Path(e) / "runtime" / "approvals_pending.json").write_text(
                    json.dumps([{"fingerprint": "abc123", "summary": "Bash(sqlmap ...)"}]),
                    encoding="utf-8")

            legs = [_Leg(cost=0.1, tool_calls=5, side_effect=defer),  # did work + deferred
                    _Leg(cost=0.1, tool_calls=0)]                      # then only waiting
            engine = _FakeEngine(legs)
            res = _drive(engine, eng, gate=_gate([2]), max_budget_usd=1000.0)
            self.assertEqual(res.reason, runloop.BLOCKED_ON_APPROVAL)
            self.assertEqual(res.invocations, 2)
            self.assertIn("await operator approval", res.stop_detail)

    def test_gate_exception_does_not_crash(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "pending"}])
            engine = _FakeEngine([_Leg(cost=0.1, tool_calls=0)])

            def boom(repo, eng_):
                raise RuntimeError("verify_completion blew up")

            # gate throws -> "cannot confirm done"; the no-progress breaker still stops the loop
            res = _drive(engine, eng, gate=boom, max_budget_usd=1000.0)
            self.assertEqual(res.reason, runloop.NO_PROGRESS)


# --- pure helpers -------------------------------------------------------------
class TestPureHelpers(unittest.TestCase):
    def test_pending_ids(self):
        led = {"categories": [{"id": "xss", "status": "pending"},
                              {"id": "sqli", "status": "attempted"},
                              {"id": "idor", "status": "pending"}]}
        self.assertEqual(runloop.pending_ids(led), frozenset({"xss", "idor"}))
        self.assertEqual(runloop.pending_ids(None), frozenset())

    def test_made_progress_first_leg(self):
        # first leg (no baseline): progress iff it did tool work or produced a finding
        self.assertTrue(runloop.made_progress(None, runloop.Snapshot(tool_calls=5)))
        self.assertTrue(runloop.made_progress(None, runloop.Snapshot(findings=1)))
        self.assertFalse(runloop.made_progress(None, runloop.Snapshot(tool_calls=0, findings=0)))

    def test_made_progress_vs_prev(self):
        prev = runloop.Snapshot(pending=frozenset({"a", "b"}), findings=0, tool_calls=3)
        # identical pending + no new findings + ~zero tool calls == no progress
        self.assertFalse(runloop.made_progress(
            prev, runloop.Snapshot(pending=frozenset({"a", "b"}), findings=0, tool_calls=0)))
        # a shrunk pending set is progress
        self.assertTrue(runloop.made_progress(
            prev, runloop.Snapshot(pending=frozenset({"a"}), findings=0, tool_calls=0)))
        # a new finding is progress
        self.assertTrue(runloop.made_progress(
            prev, runloop.Snapshot(pending=frozenset({"a", "b"}), findings=1, tool_calls=0)))
        # real tool work is progress
        self.assertTrue(runloop.made_progress(
            prev, runloop.Snapshot(pending=frozenset({"a", "b"}), findings=0, tool_calls=9)))

    def test_continue_prompt_names_outstanding(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "attempted", "findings_count": 2},
                                {"id": "sqli", "status": "pending"},
                                {"id": "idor", "status": "attempted", "findings_count": 0}])
            p = runloop.continue_prompt("acme-eng", eng)
            self.assertIn("sqli", p)       # pending -> outstanding
            self.assertIn("idor", p)       # attempted-with-0-findings -> outstanding
            self.assertNotIn("- xss", p)   # attempted-with-findings -> done, not listed
            self.assertIn("do not re-ask", p.lower())

    def test_continue_prompt_fallback_when_no_ledger(self):
        with _Eng() as eng:  # no ledger written
            p = runloop.continue_prompt("acme-eng", eng)
            self.assertIn("coverage_ledger.json", p)
            self.assertIn("write the report", p)

    def test_loop_degraded_reason(self):
        self.assertIsNone(runloop.loop_degraded_reason(
            runloop.DONE, invocations=3, cumulative_cost=1.0, max_budget=20.0,
            pending_count=0, pending_approvals=0))
        r = runloop.loop_degraded_reason(
            runloop.BUDGET_EXHAUSTED, invocations=4, cumulative_cost=19.9, max_budget=20.0,
            pending_count=5, pending_approvals=0)
        self.assertIn("budget", r.lower())
        self.assertIn("5 categor", r)
        b = runloop.loop_degraded_reason(
            runloop.BLOCKED_ON_APPROVAL, invocations=2, cumulative_cost=1.0, max_budget=20.0,
            pending_count=3, pending_approvals=2)
        self.assertIn("approval", b.lower())


class TestAnnotateRecord(unittest.TestCase):
    def _loop(self, reason, detail):
        return runloop.LoopResult(result=engines.RunResult(rc=0), reason=reason, stop_detail=detail)

    def test_done_leaves_record_untouched(self):
        rec = diagnostics.Diagnostics(outcome=diagnostics.CLEAN).to_record()
        out = runloop.annotate_record(rec, self._loop(runloop.DONE, None))
        self.assertEqual(out["outcome"], diagnostics.CLEAN)

    def test_produced_is_never_downgraded(self):
        rec = diagnostics.Diagnostics(outcome=diagnostics.PRODUCED).to_record()
        out = runloop.annotate_record(
            rec, self._loop(runloop.BUDGET_EXHAUSTED, "budget spent, 3 pending"))
        self.assertEqual(out["outcome"], diagnostics.PRODUCED)

    def test_truncated_is_marked_degraded_with_reason(self):
        rec = diagnostics.Diagnostics(outcome=diagnostics.CLEAN, degraded_reason=None).to_record()
        out = runloop.annotate_record(
            rec, self._loop(runloop.MAX_INVOCATIONS, "stopped after the max of 10 ..."))
        self.assertEqual(out["outcome"], diagnostics.DEGRADED)
        self.assertIn("stopped after the max", out["degraded_reason"])


class TestAutonomousDryRunUnchanged(unittest.TestCase):
    """The --dry-run path must NOT enter the resume loop: it prints the plan and returns, exactly
    as before the loop existed."""

    def test_autonomous_dry_run_prints_plan_and_skips_loop(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            (repo / "engagements").mkdir()
            main(["--repo", str(repo), "--no-color", "--no-banner",
                  "init", "Acme", "--authorized-by", "x", "--domain", "*.acme.com",
                  "--i-confirm-authorization"])
            eid = engagement.engagement_id("Acme")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["--repo", str(repo), "--no-color", "--no-banner",
                           "run", eid, "--autonomous", "--dry-run"])
            out = buf.getvalue()
            self.assertEqual(rc, 0, out)
            self.assertIn("DRY RUN", out)
            self.assertIn("stream-json", out)            # the autonomous argv was printed
            self.assertNotIn("autonomous loop complete", out)  # the loop was never driven


class TestBlockedCategoriesRedriven(unittest.TestCase):
    """The real failure mode: an autonomous engine ran recon + baseline, marked the vuln categories
    `blocked` ("approval-gated exploitation"), and the coverage gate PASSES (gate==0) even with no
    report. The loop must NOT call that done — it must resume and re-drive the blocked categories."""

    def test_redrivable_ids_includes_blocked(self):
        led = {"categories": [{"id": "xss", "status": "pending"},
                              {"id": "idor", "status": "blocked"},
                              {"id": "sqli", "status": "attempted", "findings_count": 0},
                              {"id": "cors", "status": "skipped"}]}
        self.assertEqual(runloop.redrivable_ids(led), frozenset({"xss", "idor"}))
        self.assertEqual(runloop.pending_ids(led), frozenset({"xss"}))  # blocked is NOT pending
        self.assertEqual(runloop.redrivable_ids(None), frozenset())

    def test_blocked_blocks_done_and_is_redriven(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "blocked"},
                                {"id": "idor", "status": "blocked"}])

            def run_them(e):  # leg 2: the re-driven categories actually run
                _write_ledger(e, [{"id": "xss", "status": "attempted", "findings_count": 1},
                                  {"id": "idor", "status": "attempted", "findings_count": 0}])

            legs = [_Leg(cost=0.1, tool_calls=8),                        # leg1: blocked, gate==0
                    _Leg(cost=0.1, tool_calls=8, side_effect=run_them)]  # leg2: runs them -> done
            engine = _FakeEngine(legs)
            # gate==0 on EVERY leg, yet leg1 must not finish because blocked categories remain
            res = _drive(engine, eng, gate=_gate([0]), max_budget_usd=100.0)
            self.assertEqual(res.invocations, 2)        # did NOT stop at leg 1
            self.assertEqual(res.reason, runloop.DONE)  # done only once nothing is blocked
            self.assertIn("xss", engine.prompts[1])     # the continue-prompt named the blocked cats
            self.assertIn("idor", engine.prompts[1])

    def test_continue_prompt_drives_blocked_without_stop_wording(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "auth-bypass", "status": "blocked"}])
            p = runloop.continue_prompt("acme-eng", eng)
            self.assertIn("auth-bypass", p)            # blocked category is named
            self.assertIn("NON-DESTRUCTIVE", p)        # told to run its detection
            # the old "stop at the gate" framing must be gone from resume prompts
            self.assertNotIn("instead of proceeding", p)
            self.assertNotIn("STOP/defer", p)


# --- rc-branching: crashed leg vs stalled leg --------------------------------
class TestDriveCrashBranching(unittest.TestCase):
    """The defect: a leg whose `claude -p` exits rc!=0 used to be indistinguishable from a leg that
    merely did no work — two crashes tripped NO_PROGRESS ("the run is stuck") and each non-final
    crash's cause was thrown away. Now a crash is branched on rc, retried, and (for resume legs)
    recovered via a fresh-session fallback; only an unrecoverable crash stops, with engine-crash."""

    def test_unrecoverable_crash_is_engine_crash_not_no_progress(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "pending"}])  # never clears
            engine = _FakeEngine([_Leg(cost=0.1, tool_calls=0, rc=1)])  # always crashes
            res = _drive(engine, eng, gate=_gate([2]), max_budget_usd=100.0)
            # the whole point: NOT reported as a stall
            self.assertEqual(res.reason, runloop.ENGINE_CRASH)
            self.assertNotEqual(res.reason, runloop.NO_PROGRESS)
            self.assertEqual(res.invocations, 1)              # one logical leg (retries are not legs)
            # default 2 retries => 3 attempts, all captured as legs (none thrown away)
            self.assertEqual(engine.run_count, 3)
            self.assertEqual(len(res.legs), 3)
            self.assertEqual([l["kind"] for l in res.legs], ["initial", "retry", "retry"])
            self.assertTrue(all(l["rc"] == 1 for l in res.legs))
            # the honest terminal reason names an ENGINE crash and explicitly disclaims "stuck"
            detail = res.stop_detail.lower()
            self.assertIn("crash", detail)
            self.assertIn("engine", detail)
            self.assertIn("not a stuck run", detail)
            # combined result propagates the non-zero rc so diagnostics classifies FAILED
            self.assertNotEqual(res.result.rc, 0)

    def test_retry_recovers_then_loop_completes(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "pending"}])

            def done(e):
                _write_ledger(e, [{"id": "xss", "status": "attempted", "findings_count": 1}])

            # attempt 1 crashes, the retry succeeds (and finishes the engagement)
            legs = [_Leg(cost=0.1, tool_calls=0, rc=1),
                    _Leg(cost=0.1, tool_calls=5, rc=0, side_effect=done)]
            engine = _FakeEngine(legs)
            # the retry completes the engagement within the first logical leg -> gate clear at once
            res = _drive(engine, eng, gate=_gate([0]), max_budget_usd=100.0)
            self.assertEqual(res.reason, runloop.DONE)
            self.assertEqual(res.invocations, 1)       # recovered within the one logical leg
            self.assertEqual(engine.run_count, 2)      # initial crash + the successful retry
            self.assertEqual([l["kind"] for l in res.legs], ["initial", "retry"])
            self.assertEqual(res.legs[0]["rc"], 1)
            self.assertEqual(res.legs[1]["rc"], 0)

    def test_crash_retries_are_bounded_and_budget_capped(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "pending"}])
            engine = _FakeEngine([_Leg(cost=0.1, tool_calls=0, rc=1)])
            with _set_env("REDSTRIKE_CRASH_RETRIES", "4"):
                res = _drive(engine, eng, gate=_gate([2]), max_budget_usd=100.0)
            self.assertEqual(res.reason, runloop.ENGINE_CRASH)
            self.assertEqual(engine.run_count, 5)      # 1 + 4 bounded retries
            self.assertEqual(len(res.legs), 5)


class TestResumeFailureFallback(unittest.TestCase):
    """A resume leg that crashes is a common un-resumable-session cause. Before giving up, the loop
    starts ONE fresh --session-id leg seeded by the continue-prompt (engagement state is persisted on
    disk), and only an unrecoverable crash after that stops the run."""

    def test_resume_crash_falls_back_to_fresh_session_and_recovers(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "pending"}])

            def still_pending(e):
                _write_ledger(e, [{"id": "xss", "status": "pending"}])  # leg1: work, not done

            def complete(e):
                _write_ledger(e, [{"id": "xss", "status": "attempted", "findings_count": 1}])

            legs = [_Leg(cost=0.1, tool_calls=5, rc=0, side_effect=still_pending),  # leg1 ok (resume=False)
                    _Leg(cost=0.1, tool_calls=0, rc=1),                              # leg2 resume CRASH
                    _Leg(cost=0.1, tool_calls=5, rc=0, side_effect=complete)]        # fresh fallback -> done
            engine = _FakeEngine(legs)
            prep = _prep()
            with _set_env("REDSTRIKE_CRASH_RETRIES", "0"):   # straight to the fallback
                res = _drive(engine, eng, gate=_gate([2, 0]), max_budget_usd=100.0, prep=prep)
            self.assertEqual(res.reason, runloop.DONE)
            self.assertEqual(res.invocations, 2)
            self.assertEqual(engine.run_count, 3)                 # leg1 + crashed resume + fresh fallback
            # the fallback leg is a FRESH --session-id leg (resume=False), after a resume (True)
            self.assertEqual(engine.resumes, [False, True, False])
            self.assertIn("Continue Redstrike engagement", engine.prompts[2])  # seeded by continue-prompt
            # a fresh session id was minted for the fallback (the resume anchor was reseeded)
            self.assertNotEqual(prep.session_id, "sess-1")
            # the crashed resume attempt + the fallback are both captured
            kinds = [l["kind"] for l in res.legs]
            self.assertIn("resume", kinds)
            self.assertIn("resume-fallback", kinds)

    def test_resume_crash_then_fallback_crash_is_engine_crash(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "pending"}])

            def still_pending(e):
                _write_ledger(e, [{"id": "xss", "status": "pending"}])

            legs = [_Leg(cost=0.1, tool_calls=5, rc=0, side_effect=still_pending),  # leg1 ok
                    _Leg(cost=0.1, tool_calls=0, rc=1),                              # resume crash
                    _Leg(cost=0.1, tool_calls=0, rc=1)]                             # fallback also crashes
            engine = _FakeEngine(legs)
            with _set_env("REDSTRIKE_CRASH_RETRIES", "0"):
                res = _drive(engine, eng, gate=_gate([2, 2]), max_budget_usd=100.0)
            self.assertEqual(res.reason, runloop.ENGINE_CRASH)
            self.assertEqual(res.invocations, 2)
            self.assertEqual(engine.resumes, [False, True, False])  # fallback attempted once
            self.assertNotEqual(res.result.rc, 0)
            kinds = [l["kind"] for l in res.legs]
            self.assertIn("resume-fallback", kinds)


class TestLegRecord(unittest.TestCase):
    """diagnostics.leg_record: per-leg cause capture (the structure the loop's legs[] holds)."""

    def test_captures_subtype_exception_and_sample(self):
        s = autorun.RunSummary(subtype="error_during_execution", tool_calls=3,
                               non_json_lines=2, non_json_sample="traceback boom")
        rec = diagnostics.leg_record(attempt=2, kind="resume", rc=1, cost=0.5, summary=s)
        self.assertEqual(rec["attempt"], 2)
        self.assertEqual(rec["kind"], "resume")
        self.assertEqual(rec["rc"], 1)
        self.assertEqual(rec["subtype"], "error_during_execution")
        self.assertEqual(rec["tool_calls"], 3)
        self.assertAlmostEqual(rec["cost"], 0.5)
        self.assertIsNotNone(rec["first_exception"])
        self.assertEqual(rec["non_json_sample"], "traceback boom")

    def test_bare_nonzero_exit_synthesizes_cause(self):
        rec = diagnostics.leg_record(attempt=1, kind="initial", rc=2, cost=0.0, summary=None)
        self.assertEqual(rec["rc"], 2)
        self.assertIsNotNone(rec["first_exception"])
        self.assertIn("code 2", diagnostics.leg_cause(rec))

    def test_clean_leg_has_no_exception(self):
        s = autorun.RunSummary(subtype="success", tool_calls=10)
        rec = diagnostics.leg_record(attempt=1, kind="initial", rc=0, cost=1.0, summary=s)
        self.assertIsNone(rec["first_exception"])
        self.assertIsNone(rec["non_json_sample"])


class TestAnnotateRecordEngineCrash(unittest.TestCase):
    def _loop(self, reason, detail, legs=None):
        return runloop.LoopResult(result=engines.RunResult(rc=1), reason=reason,
                                  stop_detail=detail, legs=legs or [])

    def test_engine_crash_is_failed_not_degraded(self):
        rec = diagnostics.Diagnostics(outcome=diagnostics.FAILED, engine_rc=1).to_record()
        legs = [diagnostics.leg_record(attempt=1, kind="resume", rc=1, cost=0.2, summary=None)]
        out = runloop.annotate_record(
            rec, self._loop(runloop.ENGINE_CRASH, "the engine CRASHED and could not be recovered", legs))
        self.assertEqual(out["outcome"], diagnostics.FAILED)
        self.assertIn("crash", out["degraded_reason"].lower())
        self.assertEqual(out["legs"], legs)          # per-leg causes are attached to the record

    def test_engine_crash_overrides_stale_clean_and_is_not_downgraded(self):
        # even if classify had said CLEAN, an engine-crash loop forces FAILED (never DEGRADED-empty)
        rec = diagnostics.Diagnostics(outcome=diagnostics.CLEAN).to_record()
        out = runloop.annotate_record(
            rec, self._loop(runloop.ENGINE_CRASH, "engine crashed; retries + fallback exhausted"))
        self.assertEqual(out["outcome"], diagnostics.FAILED)
        self.assertNotEqual(out["outcome"], diagnostics.DEGRADED)

    def test_legs_attached_for_non_crash_outcomes_too(self):
        rec = diagnostics.Diagnostics(outcome=diagnostics.CLEAN).to_record()
        legs = [diagnostics.leg_record(attempt=1, kind="initial", rc=0, cost=0.1, summary=None)]
        out = runloop.annotate_record(rec, self._loop(runloop.DONE, None, legs))
        self.assertEqual(out["outcome"], diagnostics.CLEAN)   # DONE untouched
        self.assertEqual(out["legs"], legs)                   # but legs still surfaced


def _write_chain_pending(eng_dir, pending):
    (pathlib.Path(eng_dir) / "runtime" / "chain-pending.json").write_text(
        json.dumps({"generated_at": "t", "count": len(pending), "pending": pending}), encoding="utf-8")


class TestChainPending(unittest.TestCase):
    """Guard B wiring: the SubagentStop chain_pressure hook writes runtime/chain-pending.json; the loop keeps
    the engagement out of report-ready while it is non-empty, and the continue-prompt names the feeders."""

    def test_chain_pending_readers(self):
        with _Eng() as eng:
            self.assertEqual(runloop.chain_pending_ids(eng), frozenset())
            _write_chain_pending(eng, [{"id": "RS-2026-010", "class": "cors",
                                        "anchors": ["credentialed read"]}])
            self.assertEqual(runloop.chain_pending_ids(eng), frozenset({"RS-2026-010"}))
            self.assertEqual(runloop.chain_pending_feeders(eng)[0]["class"], "cors")

    def test_continue_prompt_names_pending_feeders(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "attempted", "findings_count": 1}])
            _write_chain_pending(eng, [{"id": "RS-2026-010", "class": "cors",
                                        "anchors": ["credentialed endpoint ACAC:true"]}])
            p = runloop.continue_prompt("acme-eng", eng)
            self.assertIn("CHAIN-PRESSURE", p)
            self.assertIn("RS-2026-010", p)
            self.assertIn("attack-chain-discovery", p)

    def test_continue_prompt_no_clause_when_empty(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "pending"}])
            p = runloop.continue_prompt("acme-eng", eng)
            self.assertNotIn("CHAIN-PRESSURE", p)

    def test_pending_feeder_blocks_done_then_drains(self):
        with _Eng() as eng:
            # ledger fully covered (nothing redrivable) and the gate is CLEAR — only chain-pending remains
            _write_ledger(eng, [{"id": "xss", "status": "attempted", "findings_count": 1}])
            _write_chain_pending(eng, [{"id": "RS-2026-010", "class": "cors", "anchors": ["x"]}])

            def drain(e):  # leg 2: the chainer attempted it -> chain-pending clears
                _write_chain_pending(e, [])

            legs = [_Leg(cost=0.1, tool_calls=5),                         # leg1: gate==0 but feeder pending
                    _Leg(cost=0.1, tool_calls=5, side_effect=drain)]      # leg2: drains -> done
            engine = _FakeEngine(legs)
            res = _drive(engine, eng, gate=_gate([0]), max_budget_usd=100.0)
            self.assertEqual(res.invocations, 2)        # did NOT stop at leg 1 (feeder blocked DONE)
            self.assertEqual(res.reason, runloop.DONE)  # done only once chain-pending is empty
            self.assertIn("RS-2026-010", engine.prompts[1])  # continue-prompt named the feeder

    def test_unchained_feeder_loop_is_bounded_by_no_progress(self):
        with _Eng() as eng:
            # gate clear, nothing redrivable, no findings signal — only a never-draining chain-pending remains
            _write_ledger(eng, [{"id": "xss", "status": "attempted", "findings_count": 0}])
            _write_chain_pending(eng, [{"id": "RS-2026-010", "class": "cors", "anchors": ["x"]}])
            # the engine never chains it and does no tool work -> the no-progress breaker must stop the loop
            engine = _FakeEngine([_Leg(cost=0.1, tool_calls=0)])
            res = _drive(engine, eng, gate=_gate([0]), max_budget_usd=1000.0)
            self.assertEqual(res.reason, runloop.NO_PROGRESS)   # bounded, not an infinite chain-pressure loop
            self.assertEqual(res.invocations, 2)                # two consecutive stalls


def _write_hunt_plan(eng_dir, queue):
    (pathlib.Path(eng_dir) / "hunt_plan.json").write_text(
        json.dumps({"version": 1, "engagement": "acme-eng", "generated_at": "x",
                    "iteration": 0, "queue": queue}), encoding="utf-8")


class TestHuntPlanOrdering(unittest.TestCase):
    """#4: continue_prompt consumes hunt_plan.json — orders the outstanding set by `rank` and emits each
    class's depth_budget / diversity_pass. Absent/malformed plan falls back to ledger order."""

    def test_order_outstanding_by_rank_unranked_last(self):
        outstanding = [{"id": "xss", "status": "pending"},
                       {"id": "sqli", "status": "pending"},
                       {"id": "idor", "status": "pending"}]  # idor is NOT in the plan
        plan = {"queue": [{"rank": 2, "class": "xss", "depth_budget": {"tier": "standard"}},
                          {"rank": 1, "class": "sqli",
                           "depth_budget": {"tier": "deep", "diversity_pass": True}}]}
        ordered = runloop.order_outstanding(outstanding, plan)
        # rank 1 first, rank 2 next, unranked (idor) keeps its ledger position AFTER the ranked ones
        self.assertEqual([c["id"] for c in ordered], ["sqli", "xss", "idor"])
        self.assertEqual(ordered[0]["_rank"], 1)
        self.assertEqual(ordered[0]["_depth"], "deep")
        self.assertTrue(ordered[0]["_diversity"])
        self.assertEqual(ordered[1]["_rank"], 2)
        self.assertFalse(ordered[1]["_diversity"])
        self.assertIsNone(ordered[2]["_rank"])      # unranked -> no annotation

    def test_order_outstanding_family_fallback(self):
        # a family-level plan class (ssrf / xss) still ranks its hyphenated category ids
        outstanding = [{"id": "ssrf-cloud", "status": "pending"},
                       {"id": "xss-reflected", "status": "pending"}]
        plan = {"queue": [{"rank": 1, "class": "ssrf", "depth_budget": {"tier": "standard"}},
                          {"rank": 2, "class": "xss", "depth_budget": {"tier": "deep"}}]}
        ordered = runloop.order_outstanding(outstanding, plan)
        self.assertEqual([c["id"] for c in ordered], ["ssrf-cloud", "xss-reflected"])
        self.assertEqual(ordered[0]["_rank"], 1)
        self.assertEqual(ordered[1]["_depth"], "deep")

    def test_order_outstanding_no_plan_keeps_ledger_order(self):
        outstanding = [{"id": "ssrf-cloud", "status": "pending"},
                       {"id": "xss-reflected", "status": "pending"}]
        ordered = runloop.order_outstanding(outstanding, None)
        self.assertEqual([c["id"] for c in ordered], ["ssrf-cloud", "xss-reflected"])
        self.assertIsNone(ordered[0]["_rank"])

    def test_continue_prompt_orders_by_rank_and_emits_depth(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "pending"},
                                {"id": "sqli", "status": "pending"}])
            _write_hunt_plan(eng, [
                {"rank": 2, "class": "xss", "depth_budget": {"tier": "standard"}},
                {"rank": 1, "class": "sqli",
                 "depth_budget": {"tier": "deep", "diversity_pass": True}}])
            p = runloop.continue_prompt("acme-eng", eng)
            # ordered by rank: sqli (rank 1) listed before xss (rank 2)
            self.assertLess(p.index("- sqli"), p.index("- xss"))
            # each class's rank + depth budget + diversity pass is emitted
            self.assertIn("rank 1", p)
            self.assertIn("depth deep", p)
            self.assertIn("diversity pass", p)
            self.assertIn("rank 2", p)
            # still a resume prompt that drives concurrent waves
            self.assertIn("Continue Redstrike engagement", p)
            self.assertIn("WAVES", p)

    def test_continue_prompt_without_plan_still_names_outstanding(self):
        with _Eng() as eng:  # ledger but no hunt_plan.json
            _write_ledger(eng, [{"id": "sqli", "status": "pending"}])
            p = runloop.continue_prompt("acme-eng", eng)
            self.assertIn("- sqli", p)
            self.assertNotIn("[rank", p)  # no plan -> no per-bullet rank/depth annotation

    def test_continue_prompt_requires_per_class_labeling_and_verify(self):
        # the resume prompt must drive per-class VISIBILITY (a slug-named TaskCreate per class so the
        # console folds a distinct per-class node) and VERIFY gating (each class's own *-verify reviewer),
        # and must forbid the anonymous general-purpose family batches that hid the live headless run.
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "pending"},
                                {"id": "sqli", "status": "pending"}])
            p = runloop.continue_prompt("acme-eng", eng)
            self.assertIn("TaskCreate", p)          # per-class emission unit
            self.assertIn("per-class node", p)      # … that the console folds into a distinct node
            self.assertIn("<skill>-verify", p)      # each class handed to its own reviewer
            self.assertIn("NON-SKIPPABLE", p)       # the verify gate cannot be skipped
            self.assertIn("general-purpose", p)     # the anonymous-batch anti-pattern is named + forbidden


class TestPlanPreSteps(unittest.TestCase):
    """#4: the loop runs the plan scripts ITSELF as deterministic pre-steps instead of relying on the model.
    surface.py --plan is an idempotent merge (safe every resume); coverage.py --plan only runs when the
    ledger is absent (a rebuild would clobber progress)."""

    def test_coverage_plan_only_when_ledger_missing(self):
        calls = []
        orig = runloop._run_script
        runloop._run_script = lambda repo, rel, args, **k: (calls.append((rel, list(args))) or True)
        try:
            with _Eng() as eng:
                runloop.run_plan_steps(pathlib.Path("/repo"), eng)
                rels = [c[0] for c in calls]
                self.assertIn("surface.py", rels)
                self.assertIn("coverage.py", rels)   # ledger absent -> deterministically plan it
                calls.clear()
                _write_ledger(eng, [{"id": "xss", "status": "attempted", "findings_count": 1}])
                runloop.run_plan_steps(pathlib.Path("/repo"), eng)
                rels = [c[0] for c in calls]
                self.assertIn("surface.py", rels)        # idempotent merge still runs
                self.assertNotIn("coverage.py", rels)    # guarded off -> attempted/count preserved
        finally:
            runloop._run_script = orig

    def test_coverage_plan_passes_signals_when_present(self):
        calls = []
        orig = runloop._run_script
        runloop._run_script = lambda repo, rel, args, **k: (calls.append((rel, list(args))) or True)
        try:
            with _Eng() as eng:
                (eng / "signals.json").write_text("[]", encoding="utf-8")
                runloop.run_plan_steps(pathlib.Path("/repo"), eng)
                cov_args = next(a for r, a in calls if r == "coverage.py")
                self.assertIn("--signals", cov_args)
        finally:
            runloop._run_script = orig

    def test_run_plan_steps_best_effort_no_scripts(self):
        with _Eng() as eng:
            # real _run_script against a repo with no scripts/ -> no-op: must not raise, must not fabricate
            # a coverage ledger
            runloop.run_plan_steps(pathlib.Path(eng) / "no-such-repo", eng)
            self.assertFalse((eng / "coverage_ledger.json").is_file())

    def test_drive_runs_plan_steps_before_each_resume_leg_only(self):
        calls = []
        orig = runloop.run_plan_steps
        runloop.run_plan_steps = lambda repo, eng, **k: calls.append(str(eng))
        try:
            with _Eng() as eng:
                _write_ledger(eng, [{"id": "xss", "status": "pending"}])

                def done(e):
                    _write_ledger(e, [{"id": "xss", "status": "attempted", "findings_count": 1}])

                legs = [_Leg(cost=0.1, tool_calls=5),
                        _Leg(cost=0.1, tool_calls=5, side_effect=done)]
                engine = _FakeEngine(legs)
                res = _drive(engine, eng, gate=_gate([2, 0]))
                self.assertEqual(res.invocations, 2)
                self.assertEqual(len(calls), 1)   # ran before the one resume leg, NOT the first leg
        finally:
            runloop.run_plan_steps = orig


# --- Wave-2 (2b) multi-process worker-pool scheduler -------------------------
class _PoolLeg:
    """One scripted shard leg (per model, per wave): its cost, tool calls, rc, and an optional side effect
    that mutates the engagement dir (serialized by the fake engine's lock so test ledger writes can't tear)."""

    def __init__(self, cost=0.1, tool_calls=5, rc=0, side_effect=None):
        self.cost = cost
        self.tool_calls = tool_calls
        self.rc = rc
        self.side_effect = side_effect


class _FakePoolEngine:
    """Thread-safe fake engine for drive_pool: scripts per-MODEL wave outcomes. Records every
    build_invocation's (model, max_budget, resume, session_id), and serializes run() — including the ledger
    side effect — under a lock so concurrent shards can't tear the test's ledger writes."""

    def __init__(self, scripts, default=None):
        # scripts: {model: [ _PoolLeg per sequential run of THAT model ]}; `default` when a model runs past
        # the end of its script (e.g. a model that crashes every wave).
        self.scripts = scripts
        self.default = default or _PoolLeg(cost=0.1, tool_calls=5)
        self._lock = threading.Lock()
        self.calls = []          # (model, max_budget, resume, session_id) per build_invocation
        self.models_seen = []
        self.session_ids = []
        self.prompts = []        # the prompt each build_invocation got
        self.run_counts = {}     # per-model run index

    def build_invocation(self, prep, repo, prompt, *, mode="autonomous", allow=None, max_turns=200,
                         max_budget=20.0, resume=False, model=None, shard_models=None):
        with self._lock:
            sid = getattr(prep, "session_id", None)
            self.calls.append((model, max_budget, resume, sid))
            self.models_seen.append(model)
            self.session_ids.append(sid)
            self.prompts.append(prompt)
        return SimpleNamespace(argv=["fake"], allowed=[], model=model)

    def run(self, prep, eng_dir, inv, *, mode="autonomous", audit=None):
        with self._lock:  # serialize side effects so concurrent ledger writes stay deterministic in tests
            model = getattr(inv, "model", None)
            i = self.run_counts.get(model, 0)
            self.run_counts[model] = i + 1
            script = self.scripts.get(model, [])
            leg = script[i] if i < len(script) else self.default
            if leg.side_effect:
                leg.side_effect(pathlib.Path(eng_dir))
            s = autorun.RunSummary(cost_usd=leg.cost, tool_calls=leg.tool_calls)
            return engines.RunResult(rc=leg.rc, summary=s, started="2026-01-01T00:00:00Z",
                                     ended="2026-01-01T00:05:00Z")


class _SyncExecutor:
    """A ThreadPoolExecutor-shaped stand-in that runs each submitted task INLINE (no real threads), so the
    pool tests are fully deterministic. Mirrors the `with factory(max_workers=n) as ex: ex.submit(...)` +
    `as_completed` protocol drive_pool uses."""

    def __init__(self, max_workers=None):
        self.max_workers = max_workers

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def submit(self, fn, *args, **kw):
        f = concurrent.futures.Future()
        try:
            f.set_result(fn(*args, **kw))
        except BaseException as e:   # pragma: no cover - drive_pool traps shard errors itself
            f.set_exception(e)
        return f


class _RecordingFactory:
    """Records the max_workers drive_pool requested, then delegates to `cls` (default: the sync executor)."""

    def __init__(self, cls=_SyncExecutor):
        self.cls = cls
        self.max_workers = None
        self.made = 0

    def __call__(self, max_workers=None):
        self.max_workers = max_workers
        self.made += 1
        return self.cls(max_workers=max_workers)


def _drive_pool(engine, eng_dir, *, gate, models, max_budget_usd=100.0, first_resume=False,
                now=None, prep=None, executor_factory=None):
    return runloop.drive_pool(
        engine, prep or _prep(), pathlib.Path("/repo"), eng_dir,
        first_prompt="GO", extra_allow=[], max_turns=50, max_budget_usd=max_budget_usd,
        first_resume=first_resume, audit=eng_dir / "runtime" / "autorun.jsonl",
        engagement_id="acme-eng", shard_models=models, gate_verify=gate, emit=_silent,
        now=now, sleep=lambda _s: None, executor_factory=executor_factory,
    )


class TestShardModelList(unittest.TestCase):
    """Backward-compat DISPATCH predicate: no / one shard-model stays on `drive`; >1 selects `drive_pool`."""

    def test_normalizes_list_and_string(self):
        self.assertEqual(runloop.shard_model_list(None), [])
        self.assertEqual(runloop.shard_model_list(""), [])
        self.assertEqual(runloop.shard_model_list("x"), ["x"])
        self.assertEqual(runloop.shard_model_list("a,b"), ["a", "b"])
        self.assertEqual(runloop.shard_model_list(" a , ,b "), ["a", "b"])  # trimmed, blanks dropped
        self.assertEqual(runloop.shard_model_list(["a", "", " b "]), ["a", "b"])

    def test_dispatch_threshold(self):
        # the CLI rule: len(...) > 1 ⇒ pool, else the unchanged single-session drive
        self.assertFalse(len(runloop.shard_model_list(None)) > 1)
        self.assertFalse(len(runloop.shard_model_list("solo")) > 1)
        self.assertTrue(len(runloop.shard_model_list("a,b")) > 1)
        # drive and drive_pool are distinct entry points
        self.assertIsNot(runloop.drive, runloop.drive_pool)


class TestDrivePool(unittest.TestCase):
    def test_fanout_threads_models_and_sessions_then_completes(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "pending"},
                                {"id": "sqli", "status": "pending"}])

            def done(e):  # the "A" shard finishes the engagement in wave 1
                _write_ledger(e, [{"id": "xss", "status": "attempted", "findings_count": 1},
                                  {"id": "sqli", "status": "attempted", "findings_count": 1}])

            engine = _FakePoolEngine({
                "A": [_PoolLeg(cost=0.2, tool_calls=5, side_effect=done)],
                "B": [_PoolLeg(cost=0.3, tool_calls=5)],
            })
            factory = _RecordingFactory()
            prep = _prep()
            res = _drive_pool(engine, eng, gate=_gate([0]), models="A,B", prep=prep,
                              executor_factory=factory)

            self.assertEqual(res.reason, runloop.DONE)
            self.assertEqual(res.invocations, 1)                  # one wave
            self.assertEqual(factory.max_workers, 2)              # N shards -> N workers
            # BOTH shard models were threaded through to build_invocation
            self.assertEqual(set(engine.models_seen), {"A", "B"})
            # each shard ran as a FRESH (resume=False) leg, each with its OWN (distinct) session id
            self.assertTrue(all(resume is False for (_, _, resume, _) in engine.calls))
            self.assertEqual(len(set(engine.session_ids)), 2)
            self.assertNotIn("sess-1", engine.session_ids)        # cloned, not the shared operator session
            self.assertEqual(prep.session_id, "sess-1")           # the original prep is untouched
            # costs combine across both shards
            self.assertAlmostEqual(res.cumulative_cost, 0.5)
            self.assertAlmostEqual(res.result.summary.cost_usd, 0.5)
            # every shard attempt is aggregated + tagged with its shard/model
            self.assertEqual(len(res.legs), 2)
            self.assertEqual({l["model"] for l in res.legs}, {"A", "B"})
            self.assertEqual({l["shard"] for l in res.legs}, {0, 1})

    def test_aggregate_budget_is_partitioned_across_shards(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "pending"}])
            engine = _FakePoolEngine({
                "A": [_PoolLeg(cost=1.0, tool_calls=5,
                               side_effect=lambda e: _write_ledger(
                                   e, [{"id": "xss", "status": "attempted", "findings_count": 1}]))],
                "B": [_PoolLeg(cost=1.0, tool_calls=5)],
            })
            res = _drive_pool(engine, eng, gate=_gate([0]), models="A,B", max_budget_usd=60.0,
                              executor_factory=_RecordingFactory())
            self.assertEqual(res.reason, runloop.DONE)
            shard_budgets = [b for (_, b, _, _) in engine.calls]
            # the remaining global budget (60) is split evenly: each shard gets 30, never more
            self.assertEqual(shard_budgets, [30.0, 30.0])
            self.assertEqual(sum(shard_budgets), 60.0)            # aggregate == global, not more
            self.assertTrue(all(b <= 60.0 for b in shard_budgets))
            self.assertEqual(res.budgets, [30.0])                 # one per-shard slice recorded per wave

    def test_budget_exhausted_stops_the_pool(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "pending"}])  # never clears
            engine = _FakePoolEngine(
                {"A": [_PoolLeg(cost=3.0, tool_calls=5)], "B": [_PoolLeg(cost=3.0, tool_calls=5)]},
                default=_PoolLeg(cost=3.0, tool_calls=5),   # every wave past the script still spends 3/shard
            )
            # gate never clears; each wave spends 6; budget 10 -> exhausted before the 3rd wave
            res = _drive_pool(engine, eng, gate=_gate([2]), models="A,B", max_budget_usd=10.0,
                              executor_factory=_RecordingFactory())
            self.assertEqual(res.reason, runloop.BUDGET_EXHAUSTED)
            self.assertEqual(res.invocations, 2)                  # two waves, then the ceiling trips
            self.assertAlmostEqual(res.cumulative_cost, 12.0)
            # first wave split 10/2=5 each; second wave split (10-6)/2=2 each
            self.assertEqual(res.budgets, [5.0, 2.0])

    def test_one_shard_crashes_pool_continues_and_ends_honestly(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "pending"}])

            def complete(e):
                _write_ledger(e, [{"id": "xss", "status": "attempted", "findings_count": 1}])

            engine = _FakePoolEngine({
                "A": [_PoolLeg(cost=0.1, tool_calls=0, rc=1),      # wave1: A crashes
                      _PoolLeg(cost=0.1, tool_calls=0, rc=1)],     # wave2: A crashes again
                "B": [_PoolLeg(cost=0.1, tool_calls=5),            # wave1: B works, not done
                      _PoolLeg(cost=0.1, tool_calls=5, side_effect=complete)],  # wave2: B completes
            })
            with _set_env("REDSTRIKE_CRASH_RETRIES", "0"):         # one attempt per shard per wave
                res = _drive_pool(engine, eng, gate=_gate([2, 0]), models="A,B",
                                  executor_factory=_RecordingFactory())
            # a single crashed shard did NOT fail the run — B's progress carried it to DONE
            self.assertEqual(res.reason, runloop.DONE)
            self.assertEqual(res.invocations, 2)
            # both the crashed (A, rc=1) and the healthy (B, rc=0) attempts are captured, tagged by model
            a_legs = [l for l in res.legs if l["model"] == "A"]
            b_legs = [l for l in res.legs if l["model"] == "B"]
            self.assertTrue(a_legs and all(l["rc"] == 1 for l in a_legs))
            self.assertTrue(b_legs and all(l["rc"] == 0 for l in b_legs))

    def test_all_shards_crash_is_engine_crash(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "pending"}])
            engine = _FakePoolEngine({
                "A": [_PoolLeg(cost=0.1, tool_calls=0, rc=1)],
                "B": [_PoolLeg(cost=0.1, tool_calls=0, rc=1)],
            })
            with _set_env("REDSTRIKE_CRASH_RETRIES", "0"):
                res = _drive_pool(engine, eng, gate=_gate([2]), models="A,B",
                                  executor_factory=_RecordingFactory())
            self.assertEqual(res.reason, runloop.ENGINE_CRASH)
            self.assertNotEqual(res.reason, runloop.NO_PROGRESS)
            self.assertEqual(res.invocations, 1)
            self.assertNotEqual(res.result.rc, 0)                 # combined rc propagates the crash
            detail = (res.stop_detail or "").lower()
            self.assertIn("crash", detail)
            self.assertIn("engine", detail)

    def test_worker_exception_is_isolated_not_fatal(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "pending"}])

            class _ExplodingThenFine:
                """Shard 'A' raises from run() (a worker-level exception), 'B' completes the engagement."""

                def __init__(self):
                    self._lock = threading.Lock()
                    self.models_seen = []

                def build_invocation(self, prep, repo, prompt, *, mode="autonomous", allow=None,
                                     max_turns=200, max_budget=20.0, resume=False, model=None,
                                     shard_models=None):
                    with self._lock:
                        self.models_seen.append(model)
                    return SimpleNamespace(argv=["fake"], allowed=[], model=model)

                def run(self, prep, eng_dir, inv, *, mode="autonomous", audit=None):
                    model = getattr(inv, "model", None)
                    if model == "A":
                        raise RuntimeError("shard A blew up inside run()")
                    with self._lock:
                        _write_ledger(pathlib.Path(eng_dir),
                                      [{"id": "xss", "status": "attempted", "findings_count": 1}])
                    s = autorun.RunSummary(cost_usd=0.1, tool_calls=5)
                    return engines.RunResult(rc=0, summary=s, started="2026-01-01T00:00:00Z",
                                             ended="2026-01-01T00:05:00Z")

            engine = _ExplodingThenFine()
            with _set_env("REDSTRIKE_CRASH_RETRIES", "0"):
                res = _drive_pool(engine, eng, gate=_gate([0]), models="A,B",
                                  executor_factory=_RecordingFactory())
            # A raising did NOT crash the pool; B finished the engagement
            self.assertEqual(res.reason, runloop.DONE)
            self.assertEqual(res.invocations, 1)

    def test_real_threadpool_executor_end_to_end(self):
        # exercise the DEFAULT concurrent.futures.ThreadPoolExecutor (real threads) with the lock-guarded
        # fake engine — proves the scheduler is thread-safe end to end, not just under the sync executor.
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "xss", "status": "pending"},
                                {"id": "sqli", "status": "pending"}])

            def done(e):
                _write_ledger(e, [{"id": "xss", "status": "attempted", "findings_count": 1},
                                  {"id": "sqli", "status": "attempted", "findings_count": 1}])

            engine = _FakePoolEngine({
                "A": [_PoolLeg(cost=0.1, tool_calls=5, side_effect=done)],
                "B": [_PoolLeg(cost=0.1, tool_calls=5)],
                "C": [_PoolLeg(cost=0.1, tool_calls=5)],
            })
            res = _drive_pool(engine, eng, gate=_gate([0]), models="A,B,C",
                              executor_factory=None)   # None -> real ThreadPoolExecutor
            self.assertEqual(res.reason, runloop.DONE)
            self.assertEqual(res.invocations, 1)
            self.assertEqual(set(engine.models_seen), {"A", "B", "C"})
            self.assertEqual(len(res.legs), 3)

    def test_later_waves_use_continue_prompt(self):
        with _Eng() as eng:
            _write_ledger(eng, [{"id": "sqli", "status": "pending"}])

            def complete(e):
                _write_ledger(e, [{"id": "sqli", "status": "attempted", "findings_count": 1}])

            engine = _FakePoolEngine({
                "A": [_PoolLeg(cost=0.1, tool_calls=5),            # wave1: progress, not done
                      _PoolLeg(cost=0.1, tool_calls=5, side_effect=complete)],
                "B": [_PoolLeg(cost=0.1, tool_calls=5),
                      _PoolLeg(cost=0.1, tool_calls=5)],
            })
            res = _drive_pool(engine, eng, gate=_gate([2, 0]), models="A,B",
                              executor_factory=_RecordingFactory())
            self.assertEqual(res.reason, runloop.DONE)
            self.assertEqual(res.invocations, 2)
            # 4 build_invocations: wave1 (A,B) then wave2 (A,B), deterministic under the sync executor
            self.assertEqual(len(engine.prompts), 4)
            # wave 1 shards get the launch prompt ("GO"); wave 2 shards get the continue-prompt
            self.assertEqual(engine.prompts[0], "GO")
            self.assertEqual(engine.prompts[1], "GO")
            self.assertIn("Continue Redstrike engagement", engine.prompts[2])
            self.assertIn("Continue Redstrike engagement", engine.prompts[3])
            self.assertIn("sqli", engine.prompts[2])  # the continue-prompt names the still-outstanding class


if __name__ == "__main__":
    unittest.main()
