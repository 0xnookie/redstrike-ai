#!/usr/bin/env python3
"""
Unit tests for scripts/scan_diff.py -- the finding-level scan-diff / retest engine.

Guarantee: diffing this engagement's consolidated findings against a prior baseline classifies every
distinct finding as new / fixed / unchanged / severity-changed using dedup.py's canonical_key as identity
(so cosmetic URL differences do not split a bug), with a correct net-delta, and the JSON report validates
against skills/_contract/scan_diff.schema.json.

Stdlib only, runnable as `python test_scan_diff.py` (the CI convention).
"""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
REPO = HERE.parents[2]
sys.path.insert(0, str(SCRIPTS))

import scan_diff as sd  # noqa: E402
import structvalidate  # noqa: E402


def F(fid, asset="https://app.acme.com/x?id=1", cwe="CWE-639", sev="high", **over):
    f = {"id": fid, "title": f"Finding {fid}", "asset": asset, "category": {"cwe": cwe},
         "severity": sev, "confidence": "confirmed", "status": "verified",
         "evidence": [{"type": "log", "ref": "e"}], "reproduction": ["x"]}
    f.update(over)
    return f


class Classification(unittest.TestCase):
    def test_cosmetic_url_difference_is_unchanged(self):
        base = [F("RS-2026-001", "https://App.ACME.com:443/api/orders/?id=1")]
        curr = [F("RS-2026-010", "http://app.acme.com/api/orders?id=999")]
        s = sd.diff_findings(base, curr)["summary"]
        self.assertEqual((s["new"], s["fixed"], s["unchanged"], s["severity_changed"]), (0, 0, 1, 0))

    def test_new_fixed_unchanged_severity_changed_together(self):
        base = [F("RS-2026-001", "https://app.acme.com/a?id=1", sev="high"),
                F("RS-2026-002", "https://app.acme.com/b?id=1", sev="medium"),
                F("RS-2026-003", "https://app.acme.com/c?id=1", sev="low")]
        curr = [F("RS-2026-101", "https://app.acme.com/a?id=2", sev="medium"),
                F("RS-2026-103", "https://app.acme.com/c?id=2", sev="low"),
                F("RS-2026-104", "https://app.acme.com/d?id=2", sev="critical")]
        d = sd.diff_findings(base, curr)
        s = d["summary"]
        self.assertEqual((s["new"], s["fixed"], s["unchanged"], s["severity_changed"]), (1, 1, 1, 1))
        self.assertEqual(s["net_delta"], 0)
        self.assertEqual(d["new"][0]["id"], "RS-2026-104")
        self.assertEqual(d["fixed"][0]["id"], "RS-2026-002")
        self.assertEqual(d["severity_changed"][0]["direction"], "lowered")
        self.assertEqual(d["severity_changed"][0]["baseline_severity"], "high")
        self.assertEqual(d["severity_changed"][0]["current_severity"], "medium")

    def test_severity_raised_direction(self):
        base = [F("RS-2026-001", "https://app.acme.com/a?id=1", sev="low")]
        curr = [F("RS-2026-010", "https://app.acme.com/a?id=2", sev="critical")]
        d = sd.diff_findings(base, curr)
        self.assertEqual(d["severity_changed"][0]["direction"], "raised")

    def test_different_class_same_locus_not_merged(self):
        base = [F("RS-2026-001", "https://app.acme.com/o?id=1", cwe="CWE-639")]
        curr = [F("RS-2026-010", "https://app.acme.com/o?id=1", cwe="CWE-285")]
        s = sd.diff_findings(base, curr)["summary"]
        self.assertEqual((s["new"], s["fixed"]), (1, 1))

    def test_net_delta_positive_when_more_new(self):
        base = [F("RS-2026-001", "https://app.acme.com/a?id=1")]
        curr = [F("RS-2026-010", "https://app.acme.com/b?id=1"),
                F("RS-2026-011", "https://app.acme.com/c?id=1")]
        self.assertEqual(sd.diff_findings(base, curr)["summary"]["net_delta"], 1)


class ExtractAndShape(unittest.TestCase):
    def test_composite_and_duplicate_excluded(self):
        curr = [F("RS-2026-010", "https://app.acme.com/x?id=1"),
                F("RS-2026-011", "https://app.acme.com/y?id=1", status="duplicate"),
                F("RS-2026-012", "https://app.acme.com/z?id=1", composite=True)]
        self.assertEqual(len(sd.extract_findings(curr)), 1)

    def test_object_wrapper_shape(self):
        base = {"findings": [F("RS-2026-001", "https://app.acme.com/a?id=1")]}
        curr = {"findings": []}
        rep = sd.build_report(base, curr, generated="2026-01-01T00:00:00Z")
        self.assertEqual(rep["summary"]["fixed"], 1)
        self.assertEqual(rep["baseline"]["count"], 1)
        self.assertEqual(rep["current"]["count"], 0)

    def test_report_validates_against_schema(self):
        schema = json.loads(
            (REPO / "skills" / "_contract" / "scan_diff.schema.json").read_text(encoding="utf-8"))
        base = [F("RS-2026-001", "https://app.acme.com/a?id=1", sev="high"),
                F("RS-2026-002", "https://app.acme.com/b?id=1", sev="medium")]
        curr = [F("RS-2026-101", "https://app.acme.com/a?id=2", sev="low"),
                F("RS-2026-104", "https://app.acme.com/d?id=2", sev="critical")]
        rep = sd.build_report(base, curr, generated="2026-01-01T00:00:00Z")
        self.assertEqual(structvalidate.validate(rep, schema), [])
        # empty diff also validates
        self.assertEqual(structvalidate.validate(sd.build_report([], [], generated="t"), schema), [])


class Renders(unittest.TestCase):
    def test_markdown_has_summary_and_tables(self):
        rep = sd.build_report([F("RS-2026-001", "https://app.acme.com/a?id=1")],
                              [F("RS-2026-010", "https://app.acme.com/b?id=1")], generated="t")
        md = sd.render_markdown(rep)
        self.assertIn("Changes since last assessment", md)
        self.assertIn("Net delta", md)
        self.assertIn("## New", md)

    def test_html_is_escaped_and_tabular(self):
        rep = sd.build_report([], [F("RS-2026-010", "https://app.acme.com/b?id=1",
                                      title="<script>x</script>")], generated="t")
        h = sd.render_html(rep)
        self.assertIn("<table>", h)
        self.assertIn("&lt;script&gt;", h)
        self.assertNotIn("<script>x</script>", h)


class Cli(unittest.TestCase):
    def test_selftest(self):
        sd.selftest()

    def test_cli_writes_json_md_html(self):
        with tempfile.TemporaryDirectory() as d:
            dp = pathlib.Path(d)
            base = dp / "base.json"
            cur = dp / "cur.json"
            base.write_text(json.dumps([F("RS-2026-001", "https://app.acme.com/a?id=1")]), encoding="utf-8")
            cur.write_text(json.dumps([F("RS-2026-010", "https://app.acme.com/b?id=1")]), encoding="utf-8")
            out, md, htm = dp / "diff.json", dp / "diff.md", dp / "diff.html"
            r = subprocess.run([sys.executable, str(SCRIPTS / "scan_diff.py"),
                                "--baseline", str(base), "--current", str(cur),
                                "--out", str(out), "--md", str(md), "--html", str(htm)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            rep = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(rep["summary"]["new"], 1)
            self.assertEqual(rep["summary"]["fixed"], 1)
            self.assertTrue(md.is_file() and htm.is_file())

    def test_cli_engagement_as_current(self):
        with tempfile.TemporaryDirectory() as d:
            dp = pathlib.Path(d)
            eng = dp / "eng"
            (eng / "report").mkdir(parents=True)
            (eng / "report" / "findings_consolidated.json").write_text(
                json.dumps([F("RS-2026-010", "https://app.acme.com/b?id=1")]), encoding="utf-8")
            base = dp / "base.json"
            base.write_text(json.dumps([]), encoding="utf-8")
            out = dp / "diff.json"
            r = subprocess.run([sys.executable, str(SCRIPTS / "scan_diff.py"),
                                "--baseline", str(base), "--engagement", str(eng), "--out", str(out)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["summary"]["new"], 1)

    def test_cli_missing_file_errors(self):
        r = subprocess.run([sys.executable, str(SCRIPTS / "scan_diff.py"),
                            "--baseline", str(SCRIPTS / "nope.json"),
                            "--current", str(SCRIPTS / "nope2.json")],
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
