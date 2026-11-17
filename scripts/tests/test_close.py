#!/usr/bin/env python3
"""
Unit tests for scripts/close.py -- the interactive-Skill-path diagnostics close-writer.

Guarantee: an engagement driven through the Skill path (which never reaches the launcher's post-run
diagnostics writer) can still append ONE honest run record to runtime/diagnostics.json, so the completion
gate and the console banner read THIS engagement's outcome instead of a stale CLI-init / blocked `runs[-1]`.
The record agrees with the report regardless of the findings layout — including the per-skill executor
layout (findings under `<eng>/<skill>/findings.json`, no root file) that diagnostics.assemble under-counts.

Exercised against TEMP engagement fixtures only (never engagements/). Stdlib only, runnable as
`python test_close.py` (the CI convention).
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

import close  # noqa: E402


def _finding(fid="RS-2026-001", verdict="accepted"):
    """A finding with an explicit review verdict (what makes it reportable, mirroring the gate)."""
    return {"id": fid, "title": "t", "asset": "https://app.acme.com/x", "category": {"cwe": "CWE-79"},
            "severity": "high", "confidence": "confirmed",
            "status": "verified" if verdict == "accepted" else "rejected",
            "evidence": [{"type": "note", "ref": "x"}], "reproduction": ["a"],
            "review": {"verdict": verdict, "reviewer": "xss-reflected-verify"}}


def _runs(eng):
    doc = json.loads((eng / "runtime" / "diagnostics.json").read_text(encoding="utf-8"))
    return doc["runs"]


class TestCloseAssemblePath(unittest.TestCase):
    """The primary path: close() reuses the engine's diagnostics.assemble() for the transport + empty-vs-
    clean classification, then overlays the layout-aware reportable-finding count."""

    def _eng(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        return pathlib.Path(self._tmp.name)

    def test_root_findings_records_produced(self):
        eng = self._eng()
        (eng / "findings.json").write_text(json.dumps([_finding()]), encoding="utf-8")
        rec = close.close(eng)
        self.assertEqual(rec["outcome"], "produced-findings")
        self.assertEqual(rec["findings_count"], 1)
        self.assertEqual(_runs(eng)[-1]["outcome"], "produced-findings")

    def test_per_skill_layout_records_produced(self):
        """The real noxsframe layout: findings under <eng>/<skill>/findings.json, no root file. assemble
        (root-only) would under-count to 0 → close() must re-count across layouts and record produced."""
        eng = self._eng()
        (eng / "security-headers").mkdir()
        (eng / "security-headers" / "findings.json").write_text(
            json.dumps([_finding("RS-2026-001"), _finding("RS-2026-002", verdict="rejected")]), encoding="utf-8")
        rec = close.close(eng)
        self.assertEqual(rec["outcome"], "produced-findings")
        self.assertEqual(rec["findings_count"], 1)   # the rejected one is not reportable

    def test_zero_finding_engagement_records_explained_empty(self):
        eng = self._eng()
        (eng / "findings.json").write_text(json.dumps([]), encoding="utf-8")
        rec = close.close(eng)
        # no findings + no ledgers/transport => an explained degraded-empty (never silently 'clean')
        self.assertEqual(rec["outcome"], "degraded-empty")
        self.assertEqual(rec["findings_count"], 0)
        self.assertTrue((rec.get("degraded_reason") or "").strip())

    def test_close_appends_not_overwrites(self):
        eng = self._eng()
        (eng / "findings.json").write_text(json.dumps([_finding()]), encoding="utf-8")
        close.close(eng)
        close.close(eng)
        self.assertEqual(len(_runs(eng)), 2)   # append-only runs[]

    def test_record_shape_is_the_pinned_contract(self):
        eng = self._eng()
        (eng / "findings.json").write_text(json.dumps([_finding()]), encoding="utf-8")
        rec = close.close(eng)
        for k in ("session", "mode", "outcome", "findings_count", "transport_health",
                  "degraded_reason", "gate_summary", "phase_tally"):
            self.assertIn(k, rec)
        self.assertEqual(rec["mode"], "interactive")
        self.assertIn("hosts", rec["transport_health"])


class TestReportableCount(unittest.TestCase):
    """The layout-aware reportable-finding counter (the gate's quantity, across every layout)."""

    def _eng(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        return pathlib.Path(self._tmp.name)

    def test_counts_root_report_object_shape(self):
        eng = self._eng()
        (eng / "findings.json").write_text(
            json.dumps({"findings": [_finding("RS-2026-001"), _finding("RS-2026-002", verdict="rejected")]}),
            encoding="utf-8")
        self.assertEqual(close.reportable_count(eng), 1)

    def test_counts_verdict_file_fallback(self):
        eng = self._eng()
        f = _finding("RS-2026-010")
        del f["review"]           # no inline verdict -> read it from the verdict file
        f["status"] = "candidate"  # and no status-derived verdict either
        (eng / "security-headers").mkdir()
        (eng / "security-headers" / "findings.json").write_text(json.dumps([f]), encoding="utf-8")
        (eng / "security-headers" / "reviews").mkdir()
        (eng / "security-headers" / "reviews" / "RS-2026-010.verdict.json").write_text(
            json.dumps({"verdict": "accepted", "reviewer": "security-headers-verify"}), encoding="utf-8")
        self.assertEqual(close.reportable_count(eng), 1)

    def test_empty_engagement_counts_zero(self):
        self.assertEqual(close.reportable_count(self._eng()), 0)


class TestFallbackRecord(unittest.TestCase):
    """The import-less fallback (a stripped deployment where the cli package can't be imported): an honest
    record built the same layout-aware way, with an empty transport and an explicitly-explained empty."""

    def _eng(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        return pathlib.Path(self._tmp.name)

    def test_fallback_produced(self):
        eng = self._eng()
        (eng / "findings.json").write_text(json.dumps([_finding()]), encoding="utf-8")
        rec = close._fallback_record(eng, session="s", now="2026-01-01T00:00:00Z")
        self.assertEqual(rec["outcome"], "produced-findings")
        self.assertEqual(rec["findings_count"], 1)
        self.assertIsNone(rec["degraded_reason"])
        self.assertEqual(rec["transport_health"]["hosts"], [])

    def test_fallback_empty_is_explained(self):
        eng = self._eng()
        (eng / "findings.json").write_text(json.dumps([]), encoding="utf-8")
        rec = close._fallback_record(eng, session="", now="2026-01-01T00:00:00Z")
        self.assertEqual(rec["outcome"], "degraded-empty")
        self.assertIn("fallback", (rec["degraded_reason"] or "").lower())

    def test_fallback_write_appends(self):
        eng = self._eng()
        (eng / "findings.json").write_text(json.dumps([]), encoding="utf-8")
        rec = close._fallback_record(eng, session="", now="2026-01-01T00:00:00Z")
        close._fallback_write(eng, rec)
        close._fallback_write(eng, rec)
        self.assertEqual(len(_runs(eng)), 2)


class TestCloseCli(unittest.TestCase):
    def test_cli_runs_and_records(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "findings.json").write_text(json.dumps([_finding()]), encoding="utf-8")
            r = subprocess.run([sys.executable, str(SCRIPTS / "close.py"), "--engagement", str(eng)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("produced-findings", r.stdout)
            self.assertTrue((eng / "runtime" / "diagnostics.json").is_file())

    def test_cli_missing_engagement_errors(self):
        r = subprocess.run([sys.executable, str(SCRIPTS / "close.py"),
                            "--engagement", str(SCRIPTS / "no-such-eng-dir")],
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
