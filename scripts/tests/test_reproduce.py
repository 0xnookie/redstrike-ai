#!/usr/bin/env python3
"""
Unit tests for scripts/reproduce.py -- the MEASURED per-finding reproducibility harness that PRODUCES the
reliability counts scripts/evidence_score.py consumes.

Core guarantees:
  * it re-runs the finding's OWN benign probe and counts hits by the finding's OWN success criterion
    (OOB-callback token / status / timing / predicate) -- NEVER by a payload reflected in the body;
  * the SAFETY GUARD refuses to auto-repeat non-idempotent / state-changing / destructive / single-use probes;
  * K is bounded + clamped and runs are rate-limited (sleep injected -> testable);
  * a measured hit-rate < 0.8 is flagged "race/timing -- needs chaining" (the scorer's threshold);
  * its {runs, hits} output feeds evidence_score.py (reliability_from_json / --reliability-json), additively.

Stdlib only, runnable as `python test_reproduce.py` (the CI convention).
"""
import io
import json
import contextlib
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import reproduce as rp  # noqa: E402
import evidence_score as es  # noqa: E402


def _spec(safety=rp.SAFETY_READ_ONLY, success=None, finding_id="RS-2026-001", **kw):
    return rp.ProbeSpec(finding_id=finding_id, safety_class=safety,
                        success=success or {"kind": rp.SUCCESS_OOB_CALLBACK, "token": "tok-abc"}, **kw)


def _seq(results):
    it = iter(results)
    return lambda spec: next(it)


class SafetyGuard(unittest.TestCase):
    def test_non_repeatable_classes_are_refused(self):
        for bad in (rp.SAFETY_NON_IDEMPOTENT, rp.SAFETY_STATE_CHANGING,
                    rp.SAFETY_DESTRUCTIVE, rp.SAFETY_SINGLE_USE):
            with self.assertRaises(rp.NonRepeatableProbe):
                rp.reproduce(_spec(safety=bad), _seq([]), k=3)

    def test_read_only_and_idempotent_are_allowed(self):
        for ok in (rp.SAFETY_READ_ONLY, rp.SAFETY_IDEMPOTENT):
            r = rp.reproduce(_spec(safety=ok), _seq([rp.ProbeResult(callbacks=["tok-abc"])]), k=1, rate_rps=0)
            self.assertEqual((r.runs, r.hits), (1, 1))

    def test_refusal_message_points_to_manual_handling(self):
        try:
            rp.reproduce(_spec(safety=rp.SAFETY_DESTRUCTIVE), _seq([]), k=3)
            self.fail("destructive must raise")
        except rp.NonRepeatableProbe as e:
            self.assertIn("race-condition", str(e))
            self.assertIn("read-only / idempotent", str(e))


class SuccessCriteria(unittest.TestCase):
    def test_oob_callback_exact_match(self):
        r = rp.reproduce(_spec(), _seq([rp.ProbeResult(callbacks=["tok-abc"])] * 5), k=5, rate_rps=0)
        self.assertEqual((r.runs, r.hits, r.hit_rate), (5, 5, 1.0))

    def test_oob_callback_wrong_token_is_not_a_hit(self):
        # a different token is a miss -- there is no substring/reflection matching.
        r = rp.reproduce(_spec(), _seq([rp.ProbeResult(callbacks=["tok-OTHER"])] * 3), k=3, rate_rps=0)
        self.assertEqual(r.hits, 0)

    def test_status_criterion(self):
        sp = _spec(success={"kind": rp.SUCCESS_STATUS_IS, "expect_status": [200]})
        r = rp.reproduce(sp, _seq([rp.ProbeResult(status=200), rp.ProbeResult(status=403),
                                   rp.ProbeResult(status=200)]), k=3, rate_rps=0)
        self.assertEqual((r.runs, r.hits), (3, 2))

    def test_timing_criterion(self):
        sp = _spec(success={"kind": rp.SUCCESS_TIMING, "min_ms": 500})
        r = rp.reproduce(sp, _seq([rp.ProbeResult(elapsed_ms=800), rp.ProbeResult(elapsed_ms=120)]),
                         k=2, rate_rps=0)
        self.assertEqual((r.runs, r.hits), (2, 1))

    def test_predicate_criterion(self):
        sp = _spec(success={"kind": rp.SUCCESS_PREDICATE})
        r = rp.reproduce(sp, _seq([rp.ProbeResult(hit=True), rp.ProbeResult(hit=False),
                                   rp.ProbeResult(hit=True)]), k=3, rate_rps=0)
        self.assertEqual((r.runs, r.hits), (3, 2))

    def test_reflection_criterion_is_forbidden(self):
        for bad in sorted(rp._FORBIDDEN_SUCCESS):
            with self.assertRaises(rp.InvalidProbeSpec):
                rp.validate_success({"kind": bad, "needle": "x"})

    def test_unknown_criterion_is_forbidden(self):
        with self.assertRaises(rp.InvalidProbeSpec):
            rp.validate_success({"kind": "telepathy"})


class LoopMechanics(unittest.TestCase):
    def test_flaky_probe_is_flagged_race_timing(self):
        results = [rp.ProbeResult(callbacks=["tok-abc"])] * 5 + [rp.ProbeResult(callbacks=[])] * 5
        r = rp.reproduce(_spec(), _seq(results), k=10, rate_rps=0)
        self.assertEqual((r.runs, r.hits), (10, 5))
        self.assertAlmostEqual(r.hit_rate, 0.5)
        self.assertTrue(any("race/timing" in f for f in r.flags))

    def test_strong_hit_rate_is_not_flagged(self):
        results = [rp.ProbeResult(callbacks=["tok-abc"])] * 9 + [rp.ProbeResult(callbacks=[])]
        r = rp.reproduce(_spec(), _seq(results), k=10, rate_rps=0)
        self.assertFalse(any("race/timing" in f for f in r.flags))

    def test_k_is_clamped_high_and_low(self):
        r = rp.reproduce(_spec(), _seq([rp.ProbeResult(callbacks=["tok-abc"])] * rp.MAX_K),
                         k=9999, rate_rps=0)
        self.assertEqual(r.k_effective, rp.MAX_K)
        self.assertTrue(any("clamped" in f for f in r.flags))
        r = rp.reproduce(_spec(), _seq([rp.ProbeResult(callbacks=["tok-abc"])]), k=0, rate_rps=0)
        self.assertEqual(r.k_effective, 1)

    def test_rate_limit_sleeps_k_minus_one_times(self):
        calls = []
        rp.reproduce(_spec(), _seq([rp.ProbeResult(callbacks=["tok-abc"])] * 4), k=4, rate_rps=2.0,
                     sleep=calls.append)
        self.assertEqual(len(calls), 3)
        for c in calls:
            self.assertAlmostEqual(c, 0.5)

    def test_errored_run_counts_as_non_hit(self):
        results = [rp.ProbeResult(callbacks=["tok-abc"]), rp.ProbeResult(error="reset"),
                   rp.ProbeResult(callbacks=["tok-abc"])]
        r = rp.reproduce(_spec(), _seq(results), k=3, rate_rps=0)
        self.assertEqual((r.runs, r.hits, r.errors), (3, 2, 1))
        self.assertTrue(any("errored" in f for f in r.flags))

    def test_runner_exception_is_caught(self):
        def boom(spec):
            raise RuntimeError("boom")
        r = rp.reproduce(_spec(), boom, k=2, rate_rps=0)
        self.assertEqual((r.runs, r.hits, r.errors), (2, 0, 2))


class SpecAndResultParsing(unittest.TestCase):
    def test_from_dict_valid(self):
        s = rp.ProbeSpec.from_dict({"finding_id": "RS-2026-002", "safety_class": "read-only",
                                    "success": {"kind": "oob_callback", "token": "t"},
                                    "command": ["echo", "x"]})
        self.assertEqual(s.finding_id, "RS-2026-002")
        self.assertEqual(s.command, ["echo", "x"])

    def test_from_dict_rejects_bad_specs(self):
        for bad in ({"safety_class": "read-only", "success": {"kind": "oob_callback", "token": "t"}},
                    {"finding_id": "x", "safety_class": "nope",
                     "success": {"kind": "oob_callback", "token": "t"}},
                    {"finding_id": "x", "safety_class": "read-only", "success": {"kind": "substring"}},
                    {"finding_id": "x", "safety_class": "read-only", "success": {"kind": "oob_callback"}}):
            with self.assertRaises(rp.InvalidProbeSpec):
                rp.ProbeSpec.from_dict(bad)

    def test_probe_result_coerces_loose_json(self):
        pr = rp.ProbeResult.from_dict({"status": "200", "callbacks": "tok-abc", "elapsed_ms": "12.5"})
        self.assertEqual(pr.status, 200)
        self.assertEqual(pr.callbacks, ["tok-abc"])
        self.assertEqual(pr.elapsed_ms, 12.5)

    def test_to_dict_leads_with_contract_keys(self):
        d = rp.reproduce(_spec(), _seq([rp.ProbeResult(callbacks=["tok-abc"])] * 2), k=2, rate_rps=0).to_dict()
        self.assertEqual(list(d.keys())[:3], ["runs", "hits", "hit_rate"])
        json.dumps(d)  # serializable


class Cli(unittest.TestCase):
    def _write_spec(self, obj):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        p = pathlib.Path(tmp.name) / "probe.json"
        p.write_text(json.dumps(obj), encoding="utf-8")
        return p

    def test_dry_run_reports_safety(self):
        p = self._write_spec({"finding_id": "RS-2026-003", "safety_class": "state-changing",
                              "success": {"kind": "predicate"}})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = rp.main(["--spec", str(p), "--dry-run"])
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertFalse(out["auto_repeatable"])

    def test_refusal_exit_code(self):
        p = self._write_spec({"finding_id": "RS-2026-004", "safety_class": "destructive",
                              "success": {"kind": "predicate"}, "command": ["echo", "{}"]})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = rp.main(["--spec", str(p), "-k", "3"])
        self.assertEqual(rc, 3)
        self.assertTrue(json.loads(buf.getvalue())["refused"])

    def test_measure_read_only_probe_end_to_end(self):
        # a benign probe that prints a ProbeResult line; the subprocess runner parses it.
        snippet = "import json;print(json.dumps({'status':200}))"
        p = self._write_spec({"finding_id": "RS-2026-005", "safety_class": "read-only",
                              "success": {"kind": "status_is", "expect_status": [200]},
                              "command": [sys.executable, "-c", snippet]})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = rp.main(["--spec", str(p), "-k", "3", "--rate-rps", "0"])
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertEqual((out["runs"], out["hits"]), (3, 3))


class EvidenceScoreIntegration(unittest.TestCase):
    """The PRODUCER feeds the CONSUMER: reproduce.py {runs,hits} -> evidence_score reliability."""

    def test_reliability_from_json_dict_and_string(self):
        self.assertEqual(es.reliability_from_json({"runs": 5, "hits": 4}), (5, 4))
        self.assertEqual(es.reliability_from_json('{"runs": 10, "hits": 6}'), (10, 6))

    def test_reliability_from_json_legacy_spelling(self):
        self.assertEqual(es.reliability_from_json({"reliability_runs": 7, "reliability_hits": 7}), (7, 7))

    def test_reliability_from_json_clamps_garbage(self):
        self.assertEqual(es.reliability_from_json({"hits": -3, "runs": "oops"}), (0, 0))

    def test_measured_flaky_result_prorates_and_flags(self):
        repro = rp.reproduce(_spec(),
                             _seq([rp.ProbeResult(callbacks=["tok-abc"])] * 3
                                  + [rp.ProbeResult(callbacks=[])] * 2), k=5, rate_rps=0)
        runs, hits = es.reliability_from_json(repro.to_dict())
        self.assertEqual((runs, hits), (5, 3))
        sc = es.score_components(has_request_response=True, has_readback=True, has_impact_artifact=True,
                                 reliability_runs=runs, reliability_hits=hits)
        self.assertTrue(any("race/timing" in f for f in sc.flags))

    def test_cli_reliability_json_flag(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        rel = pathlib.Path(tmp.name) / "repro.json"
        rel.write_text(json.dumps({"runs": 20, "hits": 18}), encoding="utf-8")  # 0.9 >= 0.8 -> full credit
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = es.main(["--request-response", "--readback", "--impact",
                          "--reliability-json", str(rel)])
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertEqual((out["reliability_runs"], out["reliability_hits"]), (20, 18))
        self.assertEqual(out["score"], 75)
        self.assertEqual(out["decision"], "pass")

    def test_explicit_flags_override_reliability_json(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        rel = pathlib.Path(tmp.name) / "repro.json"
        rel.write_text(json.dumps({"runs": 10, "hits": 2}), encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = es.main(["--request-response", "--reliability-json", str(rel),
                          "--reliability-runs", "10", "--reliability-hits", "10"])
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        # explicit numbers win over the file (numbers override).
        self.assertEqual((out["reliability_runs"], out["reliability_hits"]), (10, 10))


class SelfTest(unittest.TestCase):
    def test_module_selftest(self):
        with contextlib.redirect_stdout(io.StringIO()):
            rp.selftest()


if __name__ == "__main__":
    unittest.main()
