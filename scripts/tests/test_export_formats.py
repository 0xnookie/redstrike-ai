#!/usr/bin/env python3
"""
Unit tests for scripts/export_formats.py -- the engagement-wide SARIF 2.1.0 + JUnit XML exporters.

Guarantee: a consolidated findings artifact (bare array or report object) exports to a well-formed SARIF
2.1.0 log and a CI-compatible JUnit XML, with exactly the ACCEPTED/BLOCKED findings as rows (duplicates +
composite kill-chains excluded), the severity->level map reused verbatim from the js-analysis recon exporter.

Stdlib only, runnable as `python test_export_formats.py` (the CI convention).
"""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import export_formats as ef  # noqa: E402


def F(fid, asset="https://app.acme.com/x", cwe="CWE-79", sev="high", verdict="accepted",
      status="verified", **over):
    f = {"id": fid, "title": f"Finding {fid}", "asset": asset, "category": {"cwe": cwe},
         "severity": sev, "confidence": "confirmed", "status": status,
         "evidence": [{"type": "log", "ref": "e"}], "reproduction": ["step 1"],
         "review": {"verdict": verdict, "reviewer": "x-verify"}}
    f.update(over)
    return f


class ReportableFilter(unittest.TestCase):
    def test_accepted_and_blocked_included_rest_excluded(self):
        arr = [
            F("RS-2026-001", verdict="accepted"),
            F("RS-2026-002", verdict="blocked"),
            F("RS-2026-003", verdict="rejected", status="rejected"),
            F("RS-2026-004", verdict="needs-evidence", status="open"),
            F("RS-2026-005", verdict="accepted", status="duplicate"),           # merged duplicate
            F("RS-2026-006", verdict="accepted", status="verified", composite=True),  # kill-chain
        ]
        ids = {f["id"] for f in ef.reportable_findings(arr)}
        self.assertEqual(ids, {"RS-2026-001", "RS-2026-002"})

    def test_object_wrapper_and_bare_array_equivalent(self):
        arr = [F("RS-2026-001"), F("RS-2026-002", verdict="rejected", status="rejected")]
        obj = {"engagement": "e", "findings": arr, "attack_chains": []}
        self.assertEqual([f["id"] for f in ef.reportable_findings(arr)],
                         [f["id"] for f in ef.reportable_findings(obj)])

    def test_verified_status_without_review_block_is_reportable(self):
        f = F("RS-2026-010")
        del f["review"]
        self.assertTrue(ef.is_reportable(f))
        f["status"] = "open"
        self.assertFalse(ef.is_reportable(f))


class Sarif(unittest.TestCase):
    def test_schema_version_and_tool(self):
        s = ef.build_sarif([F("RS-2026-001")], now="2026-01-01T00:00:00Z")
        self.assertEqual(s["version"], "2.1.0")
        self.assertEqual(s["$schema"], ef.SARIF_SCHEMA)
        self.assertEqual(s["runs"][0]["tool"]["driver"]["name"], "redstrike")
        self.assertEqual(s["runs"][0]["invocations"][0]["endTimeUtc"], "2026-01-01T00:00:00Z")

    def test_severity_to_level_map(self):
        rows = [F("c", sev="critical"), F("h", sev="high"), F("m", sev="medium"),
                F("l", sev="low"), F("i", sev="info")]
        s = ef.build_sarif(rows, now="t")
        lvl = {r["properties"]["finding_id"]: r["level"] for r in s["runs"][0]["results"]}
        self.assertEqual(lvl, {"c": "error", "h": "error", "m": "warning", "l": "note", "i": "note"})

    def test_one_rule_per_class_and_ruleindex_resolves(self):
        rows = [F("RS-2026-001", cwe="CWE-79"), F("RS-2026-002", cwe="CWE-79"),
                F("RS-2026-003", cwe="CWE-89")]
        run = ef.build_sarif(rows, now="t")["runs"][0]
        rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
        self.assertEqual(sorted(rule_ids), ["cwe-79", "cwe-89"])
        for res in run["results"]:
            self.assertEqual(run["tool"]["driver"]["rules"][res["ruleIndex"]]["id"], res["ruleId"])

    def test_cwe_rule_gets_help_uri(self):
        run = ef.build_sarif([F("RS-2026-001", cwe="CWE-79")], now="t")["runs"][0]
        self.assertEqual(run["tool"]["driver"]["rules"][0]["helpUri"],
                         "https://cwe.mitre.org/data/definitions/79.html")

    def test_result_location_is_asset(self):
        run = ef.build_sarif([F("RS-2026-001", asset="https://app.acme.com/s?q=1")], now="t")["runs"][0]
        uri = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "https://app.acme.com/s?q=1")

    def test_empty_is_wellformed(self):
        s = ef.build_sarif([], now="t")
        self.assertEqual(s["runs"][0]["results"], [])
        self.assertEqual(s["runs"][0]["tool"]["driver"]["rules"], [])


class JUnit(unittest.TestCase):
    def test_one_failing_case_per_finding(self):
        rows = [F("RS-2026-001"), F("RS-2026-002", sev="medium")]
        root = ET.fromstring(ef.build_junit(rows, now="t"))
        suite = root.find("testsuite")
        self.assertEqual(suite.get("tests"), "2")
        self.assertEqual(suite.get("failures"), "2")
        self.assertEqual(suite.get("errors"), "0")
        cases = suite.findall("testcase")
        self.assertEqual(len(cases), 2)
        for c in cases:
            self.assertIsNotNone(c.find("failure"))

    def test_failure_body_carries_impact_and_remediation(self):
        f = F("RS-2026-001", impact="Session theft.", remediation="Encode output.")
        root = ET.fromstring(ef.build_junit([f], now="t"))
        body = root.find("testsuite/testcase/failure").text
        self.assertIn("Impact: Session theft.", body)
        self.assertIn("Remediation: Encode output.", body)
        self.assertIn("Reproduction:", body)

    def test_empty_is_wellformed(self):
        root = ET.fromstring(ef.build_junit([], now="t"))
        self.assertEqual(root.find("testsuite").get("tests"), "0")


class WriteExports(unittest.TestCase):
    def test_writes_both_files_parseable(self):
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d) / "exports"
            data = [F("RS-2026-001"), F("RS-2026-002", verdict="rejected", status="rejected")]
            res = ef.write_exports(data, out)
            self.assertEqual(res["count"], 1)   # the rejected one is not exported
            sarif = json.loads((out / "findings.sarif").read_text(encoding="utf-8"))
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(len(sarif["runs"][0]["results"]), 1)
            root = ET.parse(out / "junit.xml").getroot()
            self.assertEqual(root.find("testsuite").get("tests"), "1")


class Cli(unittest.TestCase):
    def test_selftest(self):
        ef.selftest()

    def test_cli_input_and_outdir(self):
        with tempfile.TemporaryDirectory() as d:
            dp = pathlib.Path(d)
            cons = dp / "findings_consolidated.json"
            cons.write_text(json.dumps({"findings": [F("RS-2026-001")]}), encoding="utf-8")
            out = dp / "exports"
            r = subprocess.run([sys.executable, str(SCRIPTS / "export_formats.py"),
                                "--input", str(cons), "--out-dir", str(out)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertTrue((out / "findings.sarif").is_file())
            self.assertTrue((out / "junit.xml").is_file())

    def test_cli_engagement_layout(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "report").mkdir()
            (eng / "report" / "findings_consolidated.json").write_text(
                json.dumps([F("RS-2026-001")]), encoding="utf-8")
            r = subprocess.run([sys.executable, str(SCRIPTS / "export_formats.py"),
                                "--engagement", str(eng), "--json"],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertTrue((eng / "report" / "exports" / "findings.sarif").is_file())

    def test_cli_missing_input_errors(self):
        r = subprocess.run([sys.executable, str(SCRIPTS / "export_formats.py"),
                            "--input", str(SCRIPTS / "no-such-file.json")],
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
