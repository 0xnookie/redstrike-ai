#!/usr/bin/env python3
"""
E2 — unit tests for the recall benchmark (scripts/benchmark.py).

Centres on the modernization: `_load_findings` now reads the CURRENT findings
layouts (consolidated / root / per-skill union) and counts only REPORTED findings
(accepted/blocked, non-composite) — so recall credits what actually got reported.
Also locks the matcher semantics, findings-match scoring, the http-json dump path,
the regression check, and that the real shipped target specs pass selftest against
the live routing-map.

Stdlib only, runnable as `python test_benchmark.py` (the CI convention).
"""
import json
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import benchmark as b  # noqa: E402


def finding(cwe="CWE-89", owasp="A03:2021-Injection", title="t", status="verified",
            verdict=None, composite=False, wstg=""):
    f = {"id": "RS-2026-001", "title": title,
         "category": {"owasp": owasp, "cwe": cwe, "wstg": wstg}, "status": status}
    if verdict is not None:
        f["review"] = {"verdict": verdict, "reviewer": "x"}
    if composite:
        f["composite"] = True
    return f


def mk(path: pathlib.Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


class TestLoadFindings(unittest.TestCase):
    def test_root_layout_and_reportable_filter(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            mk(eng / "findings.json", [
                finding(cwe="CWE-89", verdict="accepted"),            # in
                finding(cwe="CWE-79", status="verified"),             # in (derived accepted)
                finding(cwe="CWE-22", verdict="blocked"),             # in (blocked is reportable)
                finding(cwe="CWE-99", verdict="rejected"),            # out
                finding(cwe="CWE-98", status="open"),                 # out (no verdict)
                finding(cwe="CWE-77", verdict="accepted", composite=True),  # out (composite)
            ])
            got = {f["cwe"] for f in b._load_findings(eng)}
            self.assertEqual(got, {"CWE-89", "CWE-79", "CWE-22"})

    def test_per_skill_union(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            mk(eng / "xss" / "findings.json", [finding(cwe="CWE-79", verdict="accepted")])
            mk(eng / "sqli" / "findings.json", [finding(cwe="CWE-89", verdict="accepted")])
            got = {f["cwe"] for f in b._load_findings(eng)}
            self.assertEqual(got, {"CWE-79", "CWE-89"})

    def test_consolidated_report(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            mk(eng / "report" / "findings_consolidated.json",
               {"findings": [finding(cwe="CWE-918", verdict="accepted")], "attack_chains": []})
            got = {f["cwe"] for f in b._load_findings(eng)}
            self.assertEqual(got, {"CWE-918"})

    def test_consolidated_wins_over_per_skill(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            mk(eng / "report" / "findings_consolidated.json", {"findings": [finding(cwe="CWE-1")]})
            mk(eng / "sqli" / "findings.json", [finding(cwe="CWE-2", verdict="accepted")])
            self.assertEqual({f["cwe"] for f in b._load_findings(eng)}, {"CWE-1"})

    def test_missing_dir_and_no_findings_exit(self):
        with self.assertRaises(SystemExit):
            b._load_findings(pathlib.Path("/no/such/eng"))
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(SystemExit):  # dir exists but has no findings file anywhere
                b._load_findings(pathlib.Path(d))


class TestMatching(unittest.TestCase):
    def f(self, **kw):
        base = {"owasp": "", "cwe": "", "wstg": "", "title": ""}
        base.update(kw)
        return base

    def test_cwe_exact_owasp_prefix_wstg_substring(self):
        self.assertTrue(b._match_expected({"cwe": "CWE-89"}, self.f(cwe="CWE-89")))
        self.assertFalse(b._match_expected({"cwe": "CWE-89"}, self.f(cwe="CWE-8")))
        self.assertTrue(b._match_expected({"owasp": "A01"}, self.f(owasp="A01:2021-BAC")))
        self.assertFalse(b._match_expected({"owasp": "A01"}, self.f(owasp="A03:2021")))
        self.assertTrue(b._match_expected({"wstg": "INPV-05"}, self.f(wstg="WSTG-INPV-05")))

    def test_title_regex_and_and_semantics(self):
        self.assertTrue(b._match_expected({"title_regex": "template injection|ssti"},
                                          self.f(title="Server-side Template Injection")))
        # ALL declared keys must match: right cwe but wrong owasp -> no match
        self.assertFalse(b._match_expected({"cwe": "CWE-89", "owasp": "A01"},
                                           self.f(cwe="CWE-89", owasp="A03")))

    def test_empty_matcher_never_matches(self):
        self.assertFalse(b._match_expected({}, self.f(cwe="CWE-89")))


class TestFindingsMatchScore(unittest.TestCase):
    def test_recall_math(self):
        target = {"target": "t", "expected": [
            {"id": "sqli", "group": "A03", "match": {"cwe": "CWE-89"}},
            {"id": "xss", "group": "A03", "match": {"cwe": "CWE-79"}},
            {"id": "ssrf", "group": "A10", "match": {"cwe": "CWE-918"}},
        ]}
        findings = [{"owasp": "A03:2021", "cwe": "CWE-89", "wstg": "", "title": "SQLi"},
                    {"owasp": "A03:2021", "cwe": "CWE-79", "wstg": "", "title": "XSS"}]
        res = b.score(b._expected_challenges(target, findings), target)
        self.assertEqual(res["overall"], {"solved": 2, "total": 3, "recall": 0.6667})
        self.assertEqual(res["by_category"]["A03"]["recall"], 1.0)
        self.assertEqual(res["by_category"]["A10"]["recall"], 0.0)
        self.assertEqual(res["unsolved"]["A10"], ["ssrf"])


class TestHttpJsonAnswerKey(unittest.TestCase):
    def test_fetch_from_dump(self):
        target = {"answer_key": {"type": "http-json", "endpoint": "/api/Challenges",
                                 "data_path": "data", "id_field": "name",
                                 "category_field": "category", "solved_field": "solved",
                                 "difficulty_field": "difficulty"}}
        with tempfile.TemporaryDirectory() as d:
            dump = pathlib.Path(d) / "challenges.json"
            mk(dump, {"data": [
                {"name": "DOM XSS", "category": "XSS", "solved": True, "difficulty": 1},
                {"name": "SQLi Login", "category": "Injection", "solved": False, "difficulty": 2},
            ]})
            rows = b.fetch_answer_key(target, answer_key_file=str(dump))
            res = b.score(rows, {"target": "juice"})
            self.assertEqual(res["overall"], {"solved": 1, "total": 2, "recall": 0.5})


class TestRegressionCheck(unittest.TestCase):
    def _res(self, solved, total, cats):
        return b.score([{"id": str(i), "category": c, "solved": i < s, "difficulty": 1}
                        for c, (s, t) in cats.items() for i in range(t)], {"target": "t"})

    def test_regression_and_improvement(self):
        base_res = b.score([{"id": "1", "category": "X", "solved": True, "difficulty": 1},
                            {"id": "2", "category": "X", "solved": True, "difficulty": 1}], {"target": "t"})
        base = b.to_baseline(base_res, "test")  # X recall 1.0
        worse = b.score([{"id": "1", "category": "X", "solved": True, "difficulty": 1},
                         {"id": "2", "category": "X", "solved": False, "difficulty": 1}], {"target": "t"})
        chk = b.check(worse, base, 0.0)
        self.assertFalse(chk["ok"])
        self.assertTrue(any(r[0] == "X" for r in chk["regressions"]))
        # within tolerance -> not a regression
        self.assertTrue(b.check(worse, base, 0.6)["ok"])


class TestPrecision(unittest.TestCase):
    """TP / confirmed-FP / FP-candidate classing + the precision range + the no-auto-fail rule."""
    TARGET = {"target": "t",
              "expected": [{"id": "sqli", "match": {"cwe": "CWE-89"}},
                           {"id": "xss", "match": {"cwe": "CWE-79"}}],
              "truth": [{"id": "ssrf", "match": {"cwe": "CWE-918"}}],
              "not_expected": [{"id": "fake-rce", "match": {"cwe": "CWE-77"}}]}

    def f(self, cwe, title):
        return {"owasp": "", "cwe": cwe, "wstg": "", "title": title}

    def test_tp_confirmed_fp_candidate_split_and_range(self):
        findings = [self.f("CWE-89", "SQLi"),       # TP (expected)
                    self.f("CWE-918", "SSRF"),      # TP (truth)
                    self.f("CWE-77", "bogus RCE"),  # confirmed FP (not_expected)
                    self.f("CWE-16", "weird hdr")]  # unlabelled -> candidate
        p = b.precision(findings, self.TARGET)
        self.assertEqual((p["true_positives"], p["confirmed_fp"], p["fp_candidates"]), (2, 1, 1))
        self.assertEqual(p["reported"], 4)
        self.assertEqual(p["precision_upper"], round(2 / 3, 4))   # TP/(TP+confirmed_FP)
        self.assertEqual(p["precision_lower"], round(2 / 4, 4))   # TP/reported
        self.assertEqual(p["fp_rate_confirmed"], round(1 / 4, 4))
        self.assertEqual(p["candidates_for_adjudication"], ["weird hdr"])
        self.assertEqual(p["confirmed_fp_titles"], ["bogus RCE"])

    def test_candidate_is_not_an_auto_fp(self):
        # an unlabelled finding must NOT raise the confirmed FP-rate (adjudication, not auto-fail).
        p = b.precision([self.f("CWE-89", "SQLi"), self.f("CWE-999", "novel bug")], self.TARGET)
        self.assertEqual(p["confirmed_fp"], 0)
        self.assertEqual(p["fp_candidates"], 1)
        self.assertEqual(p["precision_upper"], 1.0)   # candidate adjudicated out -> perfect upper bound
        self.assertEqual(p["precision_lower"], round(1 / 2, 4))

    def test_truth_defaults_to_expected_when_no_truth_block(self):
        tgt = {"target": "t", "expected": [{"id": "x", "match": {"cwe": "CWE-79"}}]}
        p = b.precision([{"owasp": "", "cwe": "CWE-79", "wstg": "", "title": "XSS"}], tgt)
        self.assertEqual(p["true_positives"], 1)
        self.assertEqual(p["precision_upper"], 1.0)


class TestTelemetry(unittest.TestCase):
    def _eng(self, d, runs, autorun_lines=None):
        eng = pathlib.Path(d)
        (eng / "runtime").mkdir(parents=True, exist_ok=True)
        mk(eng / "runtime" / "diagnostics.json", {"version": 2, "runs": runs})
        if autorun_lines is not None:
            (eng / "runtime" / "autorun.jsonl").write_text(
                "".join(json.dumps(x) + "\n" for x in autorun_lines), encoding="utf-8")
        return eng

    def test_cost_from_run_record_and_derived_metrics(self):
        runs = [
            {"session": "s1", "started": "2026-01-01T00:00:00+00:00", "ended": "2026-01-01T00:00:40+00:00",
             "findings_count": 0, "phase_tally": [{"class": "a"}, {"class": "b"}], "cost_usd": 1.0},
            {"session": "s2", "started": "2026-01-01T00:01:00+00:00", "ended": "2026-01-01T00:01:20+00:00",
             "findings_count": 2, "phase_tally": [{"class": "c"}], "cost_usd": 3.0,
             "usage": {"input_tokens": 100, "output_tokens": 50}},
        ]
        with tempfile.TemporaryDirectory() as d:
            tel = b.telemetry(self._eng(d, runs), verified_findings=2)
        self.assertEqual(tel["total_cost_usd"], 4.0)
        self.assertEqual(tel["mean_cost_per_finding_usd"], 2.0)
        self.assertEqual(tel["total_wallclock_s"], 60.0)
        self.assertEqual(tel["time_to_first_finding_s"], 60.0)  # legs up to the finding-bearing leg
        self.assertEqual(tel["total_steps"], 3)
        self.assertEqual(tel["total_tokens"], 150)

    def test_autorun_cost_is_max_per_session_not_sum(self):
        # total_cost_usd is cumulative-per-session in the engine stream: take MAX, never sum.
        runs = [{"session": "AA", "started": "2026-01-01T00:00:00+00:00",
                 "ended": "2026-01-01T00:00:10+00:00", "findings_count": 1, "phase_tally": []}]
        autorun = [
            {"type": "result", "session_id": "AA", "total_cost_usd": 5.0, "num_turns": 10,
             "usage": {"input_tokens": 10, "output_tokens": 5}},
            {"type": "result", "session_id": "AA", "total_cost_usd": 9.0, "num_turns": 1,
             "usage": {"input_tokens": 2, "output_tokens": 1}},
        ]
        with tempfile.TemporaryDirectory() as d:
            tel = b.telemetry(self._eng(d, runs, autorun), verified_findings=1)
        self.assertEqual(tel["total_cost_usd"], 9.0)     # MAX(5,9), not 14
        self.assertEqual(tel["total_tokens"], 18)        # tokens summed per-leg: 15 + 3
        self.assertEqual(tel["mean_cost_per_finding_usd"], 9.0)

    def test_cost_omitted_when_unavailable(self):
        runs = [{"session": "x", "started": "2026-01-01T00:00:00+00:00",
                 "ended": "2026-01-01T00:00:05+00:00", "findings_count": 0, "phase_tally": []}]
        with tempfile.TemporaryDirectory() as d:
            tel = b.telemetry(self._eng(d, runs), verified_findings=0)
        self.assertIsNone(tel["total_cost_usd"])
        self.assertIsNone(tel["mean_cost_per_finding_usd"])
        self.assertEqual(tel["total_wallclock_s"], 5.0)

    def test_no_diagnostics_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(b.telemetry(pathlib.Path(d), 3), {})


class TestReproducibility(unittest.TestCase):
    def test_variance_stats_and_epoch_sufficiency(self):
        eps = [{"overall": {"recall": 0.60}, "precision": {"precision_upper": 0.90}},
               {"overall": {"recall": 0.62}, "precision": {"precision_upper": 0.88}},
               {"overall": {"recall": 0.61}, "precision": {"precision_upper": 0.91}}]
        rep = b.reproducibility(eps, min_epochs=3)
        self.assertEqual(rep["epochs"], 3)
        self.assertTrue(rep["enough_epochs"])
        self.assertEqual(rep["recall"]["mean"], 0.61)
        self.assertEqual(rep["recall"]["spread"], 0.02)
        self.assertEqual(rep["precision"]["n"], 3)

    def test_under_powered_flag(self):
        rep = b.reproducibility([{"overall": {"recall": 0.5}}, {"overall": {"recall": 0.5}}], min_epochs=3)
        self.assertFalse(rep["enough_epochs"])
        self.assertIsNone(rep["precision"])  # no precision in epochs


class TestCheckExtensions(unittest.TestCase):
    def test_precision_and_fp_regression(self):
        base = {"overall": {"recall": 0.0}, "by_category": {},
                "precision": {"precision_upper": 0.9, "fp_rate_confirmed": 0.0}}
        cur = {"overall": {"recall": 0.0}, "by_category": {},
               "precision": {"precision_upper": 0.7, "fp_rate_confirmed": 0.2}}
        chk = b.check(cur, base, 0.05)
        self.assertFalse(chk["ok"])
        self.assertTrue(any(r[0] == "precision" for r in chk["regressions"]))
        self.assertTrue(any(r[0] == "fp-rate" for r in chk["regressions"]))

    def test_variance_blowout(self):
        cur = {"overall": {"recall": 0.0}, "by_category": {},
               "reproducibility": b.reproducibility(
                   [{"overall": {"recall": 0.2}}, {"overall": {"recall": 0.9}}, {"overall": {"recall": 0.5}}])}
        base = {"overall": {"recall": 0.0}, "by_category": {}}
        self.assertFalse(b.check(cur, base, 0.0, max_variance=0.1)["ok"])
        # no threshold -> variance never fails the gate
        self.assertTrue(b.check(cur, base, 0.0)["ok"])

    def test_recall_only_baseline_still_works(self):
        # a precision-less baseline (the shipped juice-shop floor) must not break check.
        base = {"overall": {"recall": 0.5}, "by_category": {}}
        cur = {"overall": {"solved": 1, "total": 2, "recall": 0.5}, "by_category": {}}
        self.assertTrue(b.check(cur, base, 0.0)["ok"])


class TestBaselineAndScoreboard(unittest.TestCase):
    def test_baseline_carries_measured_axes_only(self):
        recall_only = b.to_baseline({"target": "t", "overall": {"solved": 1, "total": 2, "recall": 0.5},
                                     "by_category": {}}, "x")
        self.assertNotIn("precision", recall_only)
        self.assertNotIn("cost", recall_only)
        full = b.to_baseline({"target": "t", "overall": {"solved": 1, "total": 2, "recall": 0.5},
                              "by_category": {},
                              "precision": {"reported": 2, "true_positives": 1, "confirmed_fp": 0,
                                            "fp_candidates": 1, "precision_upper": 1.0, "precision_lower": 0.5,
                                            "fp_rate_confirmed": 0.0},
                              "cost": {"verified_findings": 2, "total_cost_usd": 4.0,
                                       "mean_cost_per_finding_usd": 2.0, "total_tokens": 150,
                                       "total_wallclock_s": 60.0, "time_to_first_finding_s": 60.0,
                                       "total_steps": 3}}, "x")
        self.assertEqual(full["precision"]["precision_upper"], 1.0)
        self.assertEqual(full["cost"]["mean_cost_per_finding_usd"], 2.0)

    def test_scoreboard_renders_mixed_baselines(self):
        recall_only = {"target": "juice-shop", "recorded_at": "2026-01-01T00:00:00Z",
                       "overall": {"solved": 40, "total": 116, "recall": 0.3448}, "by_category": {}}
        full = {"target": "demo", "recorded_at": "2026-02-01T00:00:00Z",
                "overall": {"solved": 1, "total": 2, "recall": 0.5}, "by_category": {},
                "precision": {"precision_upper": 0.8, "precision_lower": 0.5, "fp_rate_confirmed": 0.1,
                              "true_positives": 4, "confirmed_fp": 1, "fp_candidates": 0},
                "cost": {"mean_cost_per_finding_usd": 1.25, "total_cost_usd": 5.0, "verified_findings": 4,
                         "time_to_first_finding_s": 12.0},
                "reproducibility": {"epochs": 3, "enough_epochs": True,
                                    "recall": {"stdev": 0.01, "spread": 0.02}}}
        md = b.render_scoreboard([recall_only, full])
        self.assertIn("# Redstrike benchmark scorecard", md)
        self.assertIn("juice-shop", md)
        self.assertIn("34.5%", md)      # recall-only row still renders
        self.assertIn("$1.250", md)     # full row's mean $/finding
        self.assertIn("80.0%", md)      # full row's precision
        self.assertIn("—", md)          # recall-only row's unmeasured axes render as em-dash


class TestScoreOneIntegration(unittest.TestCase):
    def test_findings_match_attaches_precision_and_cost(self):
        target = {"target": "t", "answer_key": {"type": "findings-match"},
                  "expected": [{"id": "sqli", "match": {"cwe": "CWE-89"}}],
                  "not_expected": [{"id": "fake", "match": {"cwe": "CWE-77"}}]}
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            mk(eng / "findings.json", [finding(cwe="CWE-89", verdict="accepted", title="SQLi"),
                                       finding(cwe="CWE-77", verdict="accepted", title="bogus")])
            (eng / "runtime").mkdir(parents=True, exist_ok=True)
            mk(eng / "runtime" / "diagnostics.json", {"runs": [
                {"session": "s1", "started": "2026-01-01T00:00:00+00:00",
                 "ended": "2026-01-01T00:00:30+00:00", "findings_count": 2, "phase_tally": [{"class": "x"}],
                 "cost_usd": 2.0}]})
            res = b._score_one(target, engagement=str(eng))
        self.assertIn("precision", res)
        self.assertIn("cost", res)
        self.assertEqual(res["precision"]["true_positives"], 1)
        self.assertEqual(res["precision"]["confirmed_fp"], 1)
        self.assertEqual(res["cost"]["total_cost_usd"], 2.0)
        self.assertEqual(res["cost"]["mean_cost_per_finding_usd"], 1.0)  # 2.0 / 2 reported findings


class TestRealSpecsSelftest(unittest.TestCase):
    def test_selftest_passes_against_live_routing_map(self):
        # validates the SHIPPED target specs + every category_map id vs routing-map.json
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            rc = b.selftest()
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
