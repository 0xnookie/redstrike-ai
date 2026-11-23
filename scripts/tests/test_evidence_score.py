#!/usr/bin/env python3
"""
Unit tests for scripts/evidence_score.py -- the quantified evidence-sufficiency score (the measured
accept/downgrade floor).

Core guarantees:
  * the score is built from INDEPENDENT, named-weight components (sum 100) and maps to the documented
    bands: < 55 KILL, 55-74 DOWNGRADE, >= 75 PASS;
  * RELIABILITY prorates + flags a sub-0.8 hit-rate as "race/timing -- needs chaining", while a
    deterministic (runs == 0) or >= 0.8 finding earns full credit;
  * CHAIN-DEPTH >= 2 adds a bonus;
  * the probable-cap axis (circular-only evidence) composes with the score as a SEPARATE axis;
  * white-box findings aren't unfairly killed — a code_citation substitutes for the HTTP pair;
  * aggregate() emits measured numbers over a finding set (reviewer-written scores + a derived baseline).

Stdlib only, runnable as `python test_evidence_score.py` (the CI convention).
"""
import json
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import evidence_score as es  # noqa: E402


class Weights(unittest.TestCase):
    def test_weights_sum_to_100(self):
        self.assertEqual(
            es.W_REQUEST_RESPONSE + es.W_READBACK + es.W_IMPACT_ARTIFACT
            + es.W_BROWSER_VERIFICATION + es.W_RELIABILITY + es.W_CHAIN_DEPTH, 100)

    def test_bands_ordered(self):
        self.assertLess(es.BAND_KILL, es.BAND_PASS)
        self.assertLessEqual(es.BAND_PASS, 100)


class Bands(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual(es.decision_for(54), es.DECISION_KILL)
        self.assertEqual(es.decision_for(55), es.DECISION_DOWNGRADE)
        self.assertEqual(es.decision_for(74), es.DECISION_DOWNGRADE)
        self.assertEqual(es.decision_for(75), es.DECISION_PASS)

    def test_thin_reflection_is_killed(self):
        # request/response only, deterministic, nothing read back -> 20 + 15 = 35 -> KILL.
        r = es.score_components(has_request_response=True)
        self.assertEqual(r.score, 35)
        self.assertEqual(r.decision, es.DECISION_KILL)

    def test_rr_plus_readback_is_downgrade(self):
        # 20 + 20 + 15(deterministic) = 55 -> DOWNGRADE (real but under-proven).
        r = es.score_components(has_request_response=True, has_readback=True)
        self.assertEqual(r.score, 55)
        self.assertEqual(r.decision, es.DECISION_DOWNGRADE)

    def test_rr_readback_impact_is_pass(self):
        # 20 + 20 + 20 + 15 = 75 -> PASS.
        r = es.score_components(has_request_response=True, has_readback=True, has_impact_artifact=True)
        self.assertEqual(r.score, 75)
        self.assertEqual(r.decision, es.DECISION_PASS)

    def test_score_is_clamped_0_100(self):
        full = es.score_components(has_request_response=True, has_readback=True, has_impact_artifact=True,
                                   has_browser_verification=True, chain_depth=3)
        self.assertLessEqual(full.score, 100)
        self.assertEqual(full.score, 100)  # 20+20+20+15+15+10


class Reliability(unittest.TestCase):
    def test_deterministic_full_credit(self):
        r = es.score_components(has_request_response=True, reliability_runs=0, reliability_hits=0)
        self.assertEqual(r.components["reliability"], es.W_RELIABILITY)
        self.assertFalse(any("race/timing" in f for f in r.flags))

    def test_strong_race_at_threshold_full_credit_unflagged(self):
        # hit-rate 0.9 >= 0.8 -> full credit, not flagged.
        r = es.score_components(has_request_response=True, has_readback=True, has_impact_artifact=True,
                                reliability_runs=20, reliability_hits=18)
        self.assertEqual(r.components["reliability"], es.W_RELIABILITY)
        self.assertEqual(r.decision, es.DECISION_PASS)
        self.assertFalse(any("race/timing" in f for f in r.flags))

    def test_flaky_race_prorated_and_flagged(self):
        # hit-rate 0.5 < 0.8 -> prorated to 7.5, flagged needs-chaining.
        r = es.score_components(has_request_response=True, has_readback=True, has_impact_artifact=True,
                                reliability_runs=10, reliability_hits=5)
        self.assertEqual(r.components["reliability"], round(es.W_RELIABILITY * 0.5, 2))
        self.assertTrue(any("race/timing -- needs chaining" in f for f in r.flags))
        self.assertEqual(r.decision, es.DECISION_DOWNGRADE)  # 67.5 -> 68

    def test_zero_hits_is_flagged(self):
        r = es.score_components(has_request_response=True, reliability_runs=5, reliability_hits=0)
        self.assertEqual(r.components["reliability"], 0)
        self.assertTrue(any("race/timing" in f for f in r.flags))

    def test_hits_cannot_exceed_runs(self):
        # defensive: hits > runs is clamped to a 1.0 hit-rate (full credit), never > W_RELIABILITY.
        r = es.score_components(has_request_response=True, reliability_runs=3, reliability_hits=9)
        self.assertEqual(r.components["reliability"], es.W_RELIABILITY)

    def test_counts_echoed_in_result(self):
        r = es.score_components(has_request_response=True, reliability_runs=7, reliability_hits=6)
        self.assertEqual(r.reliability_runs, 7)
        self.assertEqual(r.reliability_hits, 6)


class ChainDepth(unittest.TestCase):
    def test_depth_2_adds_bonus(self):
        base = es.score_components(has_request_response=True, has_readback=True)
        deep = es.score_components(has_request_response=True, has_readback=True, chain_depth=2)
        self.assertEqual(deep.components["chain_depth"], es.W_CHAIN_DEPTH)
        self.assertEqual(deep.score, base.score + es.W_CHAIN_DEPTH)

    def test_depth_1_no_bonus(self):
        self.assertEqual(es.score_components(chain_depth=1).components["chain_depth"], 0)

    def test_deep_chain_bonus(self):
        self.assertEqual(es.score_components(chain_depth=5).components["chain_depth"], es.W_CHAIN_DEPTH)


class ProbableCap(unittest.TestCase):
    def test_circular_only_is_capped(self):
        # effect seen only in the skill's own log: no request_response / browser / independent artifact.
        r = es.score_components(has_readback=True, has_impact_artifact=True, has_independent_artifact=False)
        self.assertTrue(r.probable_cap)
        self.assertTrue(any("probable" in f for f in r.flags))

    def test_request_response_lifts_cap(self):
        self.assertFalse(es.score_components(has_request_response=True).probable_cap)

    def test_browser_lifts_cap(self):
        self.assertFalse(es.score_components(has_browser_verification=True).probable_cap)

    def test_independent_flag_lifts_cap(self):
        self.assertFalse(es.score_components(has_independent_artifact=True).probable_cap)

    def test_cap_is_independent_of_score(self):
        # a HIGH score can still be probable-capped if (hypothetically) no independent artifact backs it.
        r = es.score_components(has_readback=True, has_impact_artifact=True, chain_depth=2,
                                has_independent_artifact=False)
        self.assertTrue(r.probable_cap)


class Rounding(unittest.TestCase):
    def test_half_up(self):
        self.assertEqual(es._round_half_up(74.5), 75)
        self.assertEqual(es._round_half_up(74.4), 74)
        self.assertEqual(es._round_half_up(0.5), 1)


class FindingExtraction(unittest.TestCase):
    def test_request_response_and_poc(self):
        f = {"evidence": [{"type": "request_response", "ref": "a"}, {"type": "poc_script", "ref": "b"}]}
        i = es.inputs_from_finding(f)
        self.assertTrue(i.has_request_response)
        self.assertTrue(i.has_independent_artifact)
        self.assertFalse(i.white_box)

    def test_dom_capture_is_browser(self):
        i = es.inputs_from_finding({"evidence": [{"type": "dom_capture", "ref": "d"}]})
        self.assertTrue(i.has_browser_verification)
        self.assertTrue(i.has_independent_artifact)

    def test_semantic_components_default_off(self):
        # an evidence TYPE alone cannot prove readback / impact — those stay reviewer-asserted.
        i = es.inputs_from_finding({"evidence": [{"type": "request_response", "ref": "a"}]})
        self.assertFalse(i.has_readback)
        self.assertFalse(i.has_impact_artifact)

    def test_white_box_substitution(self):
        wb = {"evidence": [{"type": "code_citation", "file": "a.php", "line": 1, "snippet": "x"}]}
        i = es.inputs_from_finding(wb)
        self.assertTrue(i.white_box)
        self.assertTrue(i.has_request_response)      # code_citation substitutes for the HTTP pair
        self.assertTrue(i.has_independent_artifact)
        r = es.score(i)
        self.assertEqual(r.components["request_response"], es.W_REQUEST_RESPONSE)
        self.assertTrue(any("white-box" in f for f in r.flags))

    def test_circular_only_finding_is_capped_and_killed(self):
        circ = es.inputs_from_finding(
            {"evidence": [{"type": "log", "ref": "x"}, {"type": "tool_output", "ref": "y"}]})
        self.assertFalse(circ.has_independent_artifact)
        r = es.score(circ)
        self.assertTrue(r.probable_cap)
        self.assertEqual(r.decision, es.DECISION_KILL)

    def test_composite_implies_chain_depth(self):
        i = es.inputs_from_finding({"composite": True, "evidence": [{"type": "request_response", "ref": "a"}]})
        self.assertGreaterEqual(i.chain_depth, es.CHAIN_DEPTH_MIN)

    def test_reliability_read_from_prior_block(self):
        f = {"evidence": [{"type": "request_response", "ref": "a"}],
             "evidence_score": {"score": 60, "decision": "downgrade",
                                "reliability_runs": 10, "reliability_hits": 6}}
        i = es.inputs_from_finding(f)
        self.assertEqual(i.reliability_runs, 10)
        self.assertEqual(i.reliability_hits, 6)

    def test_non_dict_finding_is_safe(self):
        i = es.inputs_from_finding("not a dict")  # type: ignore[arg-type]
        self.assertIsInstance(i, es.EvidenceInputs)


class ToDict(unittest.TestCase):
    def test_shape_matches_schema(self):
        d = es.score_components(has_request_response=True, has_readback=True).to_dict()
        self.assertEqual(set(d.keys()),
                         {"score", "decision", "components", "reliability_runs", "reliability_hits",
                          "probable_cap", "flags"})
        self.assertIsInstance(d["components"], dict)
        self.assertEqual(set(d["components"].keys()),
                         {"request_response", "readback", "impact_artifact",
                          "browser_verification", "reliability", "chain_depth"})
        # every component value is a number (schema: components.additionalProperties = {type: number}).
        for v in d["components"].values():
            self.assertIsInstance(v, (int, float))
        self.assertIn(d["decision"], (es.DECISION_KILL, es.DECISION_DOWNGRADE, es.DECISION_PASS))


class Aggregate(unittest.TestCase):
    def test_empty_is_zero(self):
        a = es.aggregate([])
        self.assertEqual(a["n"], 0)
        self.assertEqual(a["by_decision"], {"pass": 0, "downgrade": 0, "kill": 0})

    def test_mixed_reviewer_and_derived(self):
        a = es.aggregate([
            {"id": "RS-2026-001", "evidence_score": {"score": 80, "decision": "pass",
                                                     "reliability_runs": 0, "reliability_hits": 0}},
            {"id": "RS-2026-002", "evidence": [{"type": "log", "ref": "x"}]},  # derived -> KILL, capped
        ])
        self.assertEqual(a["n"], 2)
        self.assertEqual(a["scored_by_reviewer"], 1)
        self.assertEqual(a["derived"], 1)
        self.assertEqual(a["by_decision"]["pass"], 1)
        self.assertEqual(a["by_decision"]["kill"], 1)
        self.assertEqual(a["probable_capped"], 1)
        self.assertEqual(a["max"], 80)

    def test_race_flag_counted(self):
        a = es.aggregate([
            {"id": "RS-2026-003",
             "evidence_score": {"score": 68, "decision": "downgrade",
                                "reliability_runs": 10, "reliability_hits": 5,
                                "flags": ["race/timing -- needs chaining (hit-rate 0.50 < 0.8)"]}},
        ])
        self.assertEqual(a["flagged_race_timing"], 1)

    def test_ignores_non_dicts(self):
        a = es.aggregate([None, 3, {"id": "RS-2026-004", "evidence": [{"type": "request_response", "ref": "a"}]}])
        self.assertEqual(a["n"], 1)


class LoadAndAggregateEngagement(unittest.TestCase):
    def _eng(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return pathlib.Path(tmp.name)

    def test_load_findings_across_layouts_deduped(self):
        eng = self._eng()
        (eng / "idor").mkdir()
        (eng / "idor" / "findings.json").write_text(json.dumps(
            [{"id": "RS-2026-010", "evidence": [{"type": "request_response", "ref": "a"}]}]), encoding="utf-8")
        (eng / "findings.json").write_text(json.dumps(
            [{"id": "RS-2026-010"},  # duplicate id -> first wins
             {"id": "RS-2026-011", "evidence": [{"type": "log", "ref": "x"}]}]), encoding="utf-8")
        got = {f["id"] for f in es.load_findings(eng)}
        self.assertEqual(got, {"RS-2026-010", "RS-2026-011"})
        self.assertEqual(len(es.load_findings(eng)), 2)  # deduped

    def test_aggregate_engagement(self):
        eng = self._eng()
        (eng / "findings.json").write_text(json.dumps([
            {"id": "RS-2026-020",
             "evidence_score": {"score": 90, "decision": "pass",
                                "reliability_runs": 0, "reliability_hits": 0}},
            {"id": "RS-2026-021", "evidence": [{"type": "log", "ref": "x"}]},
        ]), encoding="utf-8")
        a = es.aggregate_engagement(eng)
        self.assertEqual(a["n"], 2)
        self.assertEqual(a["by_decision"]["pass"], 1)
        self.assertEqual(a["by_decision"]["kill"], 1)

    def test_consolidated_object_shape(self):
        eng = self._eng()
        (eng / "report").mkdir()
        (eng / "report" / "findings_consolidated.json").write_text(json.dumps(
            {"engagement": "x", "findings": [
                {"id": "RS-2026-030", "evidence": [{"type": "request_response", "ref": "a"}]}],
             "attack_chains": [{"id": "RS-2026-031", "composite": True,
                                "evidence": [{"type": "request_response", "ref": "b"}]}]}), encoding="utf-8")
        self.assertEqual(len(es.load_findings(eng)), 2)


class Cli(unittest.TestCase):
    def test_explicit_flags(self):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = es.main(["--request-response", "--readback", "--impact"])
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertEqual(out["score"], 75)
        self.assertEqual(out["decision"], "pass")
        self.assertFalse(out["probable_cap"])

    def test_file_mode_with_flags(self):
        import io
        import contextlib
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        ff = pathlib.Path(tmp.name) / "findings.json"
        ff.write_text(json.dumps([{"id": "RS-2026-040",
                                   "evidence": [{"type": "request_response", "ref": "a"}]}]), encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = es.main(["--file", str(ff), "--id", "RS-2026-040", "--readback", "--impact"])
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        # request_response derived from the finding + readback/impact from flags -> PASS.
        self.assertEqual(out["score"], 75)
        self.assertEqual(out["decision"], "pass")

    def test_aggregate_cli(self):
        import io
        import contextlib
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        eng = pathlib.Path(tmp.name)
        (eng / "findings.json").write_text(json.dumps(
            [{"id": "RS-2026-050", "evidence": [{"type": "request_response", "ref": "a"}]}]), encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = es.main(["--engagement", str(eng), "--aggregate"])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(buf.getvalue())["n"], 1)


class SelfTest(unittest.TestCase):
    def test_module_selftest(self):
        es.selftest()


if __name__ == "__main__":
    unittest.main()
