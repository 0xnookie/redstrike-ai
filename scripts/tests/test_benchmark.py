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
