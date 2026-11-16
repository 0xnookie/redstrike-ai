import io
import json
import os
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace

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


def _drive(engine, eng_dir, *, gate, max_budget_usd=100.0, first_resume=False, now=None):
    return runloop.drive(
        engine, _prep(), pathlib.Path("/repo"), eng_dir,
        first_prompt="GO", extra_allow=[], max_turns=50, max_budget_usd=max_budget_usd,
        first_resume=first_resume, audit=eng_dir / "runtime" / "autorun.jsonl",
        engagement_id="acme-eng", gate_verify=gate, emit=_silent, now=now,
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


if __name__ == "__main__":
    unittest.main()
