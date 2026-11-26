#!/usr/bin/env python3
"""
Unit tests for scripts/finding_emit.py -- the single owner of finding emission (shift-left, QW-1).

Guarantee: a finding is validated at WRITE time (in the executor that holds the context), so a bad finding
is refused BEFORE handback instead of 5 completion-gate rounds later. Three modes:
  * --alloc-id   : the one owner of RS-YYYY-NNN allocation (there was none before -> executors invented slugs).
  * --skeleton   : a fully schema-conformant stub (so the shape is never reconstructed from memory).
  * --validate   : the gate's EXACT finding-schema check, full violation list + coercion hints.

Stdlib only, runnable as `python test_finding_emit.py` (the CI convention).
"""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import finding_emit as fe  # noqa: E402


def _bad_finding():
    """The 20min bola-bfla incident shape: invented slug id, TitleCase severity, a prose-STRING evidence,
    and a stray non-schema property -- the ~8-axis violation the parent hand-fixed one gate-round at a time."""
    return {"id": "RS-20min-bfla-extcomment-author-spoof", "title": "author spoof",
            "asset": "https://api.20min.ch/comments", "category": {"cwe": "CWE-285"},
            "severity": "Low", "confidence": "confirmed", "status": "open",
            "evidence": "we posted a comment as another author (see log)", "reproduction": ["POST /comments"],
            "endpoint": "/comments", "method": "POST"}


class AllocId(unittest.TestCase):
    def _eng(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        return pathlib.Path(self._tmp.name)

    def test_first_id_is_001(self):
        self.assertEqual(fe.alloc_id(self._eng(), year=2026), "RS-2026-001")

    def test_skips_used_ids_from_any_findings_file(self):
        eng = self._eng()
        (eng / "idor").mkdir()
        (eng / "idor" / "findings.json").write_text(json.dumps([{"id": "RS-2026-002"}]), encoding="utf-8")
        # a NON-canonical stray file must ALSO reserve its sequence (never reuse an id that lives there).
        (eng / "bola-bfla").mkdir()
        (eng / "bola-bfla" / "findings_authed_bfla.json").write_text(
            json.dumps([{"id": "RS-2026-007"}]), encoding="utf-8")
        self.assertEqual(fe.alloc_id(eng, year=2026), "RS-2026-008")  # max(002,007)+1

    def test_scans_review_verdict_sidecars(self):
        eng = self._eng()
        (eng / "reviews").mkdir()
        (eng / "reviews" / "RS-2026-005.verdict.json").write_text(
            json.dumps({"verdict": "accepted", "reviewer": "idor-verify"}), encoding="utf-8")
        self.assertEqual(fe.alloc_id(eng, year=2026), "RS-2026-006")

    def test_concurrent_allocs_do_not_collide(self):
        """Two back-to-back allocations (the concurrent-subagent case) hand out DISTINCT ids because the
        first is RESERVED in the reservation ledger before the second scans."""
        eng = self._eng()
        a = fe.alloc_id(eng, year=2026)
        b = fe.alloc_id(eng, year=2026)
        self.assertEqual((a, b), ("RS-2026-001", "RS-2026-002"))

    def test_per_year_sequence(self):
        eng = self._eng()
        (eng / "findings.json").write_text(json.dumps([{"id": "RS-2025-099"}]), encoding="utf-8")
        self.assertEqual(fe.alloc_id(eng, year=2026), "RS-2026-001")  # a prior-year id doesn't bump 2026

    def test_cli_prints_bare_id(self):
        eng = self._eng()
        r = subprocess.run([sys.executable, str(SCRIPTS / "finding_emit.py"), "--alloc-id",
                            "--engagement", str(eng), "--year", "2026"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "RS-2026-001")


class Skeleton(unittest.TestCase):
    def test_skeleton_is_schema_conformant(self):
        viols = fe.validate_finding(fe.skeleton(year=2026))
        self.assertEqual(viols, [], viols)

    def test_cli_skeleton_is_valid_json_with_required_keys(self):
        r = subprocess.run([sys.executable, str(SCRIPTS / "finding_emit.py"), "--skeleton"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        f = json.loads(r.stdout)
        for k in ("id", "title", "asset", "category", "severity", "confidence", "status",
                  "evidence", "reproduction"):
            self.assertIn(k, f)
        self.assertIsInstance(f["evidence"], list)            # NOT a prose string
        self.assertEqual(f["severity"], "low")                # lowercase enum


class Validate(unittest.TestCase):
    def test_flags_all_four_incident_violations(self):
        viols = fe.validate_finding(_bad_finding())
        blob = " ".join(v["error"] for v in viols)
        self.assertIn("does not match pattern", blob)              # bad id (slug)
        self.assertIn("'Low' not one of", blob)                    # severity case
        self.assertIn("expected array", blob)                      # prose-string evidence
        self.assertIn("unexpected property 'endpoint'", blob)      # extra prop
        self.assertIn("unexpected property 'method'", blob)

    def test_violations_are_not_truncated(self):
        """The gate truncates to [:4]; this validator prints them ALL (the whole point)."""
        viols = fe.validate_finding(_bad_finding())
        self.assertGreater(len(viols), 4)

    def test_coercion_hints_present(self):
        viols = fe.validate_finding(_bad_finding())
        hints = " ".join(v["hint"] for v in viols)
        self.assertIn("lowercase -> 'low'", hints)                 # severity coercion
        self.assertIn("must be a LIST of {type,ref}", hints)       # evidence coercion
        self.assertIn("fold into `asset`", hints)                  # endpoint relocation
        self.assertIn("--alloc-id", hints)                         # id allocation

    def test_missing_required_field_flagged(self):
        f = fe.skeleton(year=2026)
        del f["asset"]
        viols = fe.validate_finding(f)
        self.assertTrue(any("missing/empty required field 'asset'" in v["error"] for v in viols))

    def test_validate_file_array_and_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "findings.json"
            p.write_text(json.dumps([_bad_finding(), fe.skeleton(year=2026)]), encoding="utf-8")
            ok, lines, total = fe.validate_file(p)
            self.assertFalse(ok)
            self.assertGreater(total, 0)
            # the conformant second finding PASSES while the first FAILS.
            self.assertTrue(any(l.startswith("PASS  finding #2") for l in lines))
            self.assertTrue(any(l.startswith("FAIL  finding #1") for l in lines))

    def test_cli_validate_exit_nonzero(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "f.json"
            p.write_text(json.dumps(_bad_finding()), encoding="utf-8")
            r = subprocess.run([sys.executable, str(SCRIPTS / "finding_emit.py"), "--validate", str(p)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 2, r.stdout)
            self.assertIn("FAIL", r.stdout)

    def test_cli_validate_clean_exit_zero(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "f.json"
            p.write_text(json.dumps([fe.skeleton(year=2026)]), encoding="utf-8")
            r = subprocess.run([sys.executable, str(SCRIPTS / "finding_emit.py"), "--validate", str(p)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("PASS", r.stdout)


class SelfTest(unittest.TestCase):
    def test_module_selftest_passes(self):
        self.assertEqual(fe.selftest(), 0)


if __name__ == "__main__":
    unittest.main()
