#!/usr/bin/env python3
"""
Unit tests for scripts/model_ledger.py -- the cross-model dispatch ledger (roadmap L-H): MEASURE what the
`model:` pin ASSERTS.

Covers: model_family normalization (the exact "same model family" rule), record/read round-trip, lock-safe
CONCURRENT appends (a wave's parallel subagents each record without clobbering), diversity_assessment
(cross_model True when the adversary ran on a different family than the executors, False when all same /
unmeasurable), and that the schema VALIDATES a well-formed ledger and REJECTS a malformed entry.

Stdlib only, runnable as `python test_model_ledger.py` (the CI convention).
"""
import json
import pathlib
import sys
import tempfile
import threading
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
REPO = HERE.parents[2]
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(REPO / "skills" / "_contract"))

import model_ledger as ml  # noqa: E402
import verify_completion as vc  # noqa: E402 — reuse the real schema-validation path the gate uses

SCHEMA_REL = "skills/_contract/model_ledger.schema.json"


class ModelFamily(unittest.TestCase):
    """The exact normalization the same-model check compares."""

    def test_opus_spellings(self):
        for s in ("opus", "Opus", "claude-opus-4-8", "Opus 4.8", "us.anthropic.claude-opus-4"):
            self.assertEqual(ml.model_family(s), "opus", s)

    def test_sonnet_and_haiku(self):
        self.assertEqual(ml.model_family("claude-sonnet-4-5-20250101"), "sonnet")
        self.assertEqual(ml.model_family("Sonnet 5.5"), "sonnet")
        self.assertEqual(ml.model_family("claude-3-5-haiku-20241022"), "haiku")

    def test_empty(self):
        self.assertEqual(ml.model_family(""), "")
        self.assertEqual(ml.model_family(None), "")

    def test_same_family_different_spelling(self):
        self.assertEqual(ml.model_family("opus"), ml.model_family("claude-opus-4-8"))
        self.assertNotEqual(ml.model_family("opus"), ml.model_family("sonnet"))


class RecordRead(unittest.TestCase):
    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            e = ml.record(eng, "executor", "xss", "claude-opus-4-8", agent_id="xss-reflected")
            self.assertEqual(e["role"], "executor")
            self.assertEqual(e["model_family"], "opus")
            self.assertEqual(e["agent_id"], "xss-reflected")
            led = ml.read(eng)
            self.assertEqual(led["version"], ml.SCHEMA_VERSION)
            self.assertEqual(led["engagement"], eng.name)
            self.assertEqual(len(led["entries"]), 1)
            self.assertEqual(led["entries"][0]["category"], "xss")
            # the file lives under runtime/
            self.assertTrue((eng / "runtime" / "model_ledger.json").is_file())

    def test_adversary_category_is_null(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            e = ml.record(eng, "exhaustion-adversary", None, "sonnet")
            self.assertIsNone(e["category"])

    def test_missing_ledger_reads_empty(self):
        with tempfile.TemporaryDirectory() as d:
            led = ml.read(pathlib.Path(d))
            self.assertEqual(led["entries"], [])

    def test_bad_role_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                ml.record(pathlib.Path(d), "banana", "xss", "opus")

    def test_empty_model_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                ml.record(pathlib.Path(d), "executor", "xss", "")

    def test_concurrent_appends_are_lock_safe(self):
        """A wave's parallel subagents each record once; every record must survive (no last-write-wins clobber)."""
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            N = 24

            def worker(i):
                ml.record(eng, "executor", f"class-{i}", "opus" if i % 2 else "sonnet")

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            led = ml.read(eng)
            self.assertEqual(len(led["entries"]), N, "a concurrent record was clobbered")
            self.assertEqual({e["category"] for e in led["entries"]}, {f"class-{i}" for i in range(N)})


class Diversity(unittest.TestCase):
    def test_cross_model_true_when_adversary_differs(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            ml.record(eng, "executor", "xss", "opus")
            ml.record(eng, "executor", "sqli", "claude-opus-4-8")   # same family, different spelling
            ml.record(eng, "exhaustion-adversary", None, "sonnet")
            a = ml.diversity_assessment(eng)
            self.assertTrue(a["cross_model_available"])
            self.assertEqual(a["executors_models"], ["opus"])
            self.assertEqual(a["adversary_model"], "sonnet")

    def test_cross_model_false_when_all_same(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            ml.record(eng, "executor", "xss", "opus")
            ml.record(eng, "reviewer", "xss", "opus", agent_id="xss-reflected-verify")
            ml.record(eng, "exhaustion-adversary", None, "claude-opus-4-8")   # STILL opus — the collapse
            a = ml.diversity_assessment(eng)
            self.assertFalse(a["cross_model_available"])
            self.assertEqual(a["adversary_model"], "opus")
            self.assertIn("same model family", a["reason"].lower())

    def test_cross_model_true_via_reviewer(self):
        """A `*-verify` reviewer on a different family than the executors also counts as cross-model."""
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            ml.record(eng, "executor", "xss", "opus")
            ml.record(eng, "reviewer", "xss", "sonnet", agent_id="xss-reflected-verify")
            a = ml.diversity_assessment(eng)
            self.assertTrue(a["cross_model_available"])
            self.assertEqual(a["reviewers_models"], ["sonnet"])

    def test_unmeasurable_without_executors(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            ml.record(eng, "exhaustion-adversary", None, "sonnet")  # no executor recorded
            a = ml.diversity_assessment(eng)
            self.assertFalse(a["cross_model_available"])
            self.assertEqual(a["executors_models"], [])
            self.assertIn("cannot be measured", a["reason"])


class Schema(unittest.TestCase):
    def test_valid_ledger_validates(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            ml.record(eng, "executor", "xss", "opus", agent_id="xss-reflected")
            ml.record(eng, "exhaustion-adversary", None, "sonnet")
            led = ml.read(eng)
            ok, note = vc._validate_against_schema(led, SCHEMA_REL)
            self.assertTrue(ok, note)

    def test_malformed_entry_rejected(self):
        bad = {"version": 1, "engagement": "x", "entries": [
            {"role": "wizard", "model": "opus", "ts": "2026-01-01T00:00:00Z"}]}  # role not in enum
        ok, note = vc._validate_against_schema(bad, SCHEMA_REL)
        self.assertFalse(ok, note)

    def test_unexpected_property_rejected(self):
        bad = {"version": 1, "engagement": "x", "entries": [
            {"role": "executor", "model": "opus", "ts": "2026-01-01T00:00:00Z", "surprise": 1}]}
        ok, note = vc._validate_against_schema(bad, SCHEMA_REL)
        self.assertFalse(ok, note)

    def test_missing_required_field_rejected(self):
        bad = {"version": 1, "engagement": "x", "entries": [{"role": "executor", "ts": "t"}]}  # no model
        ok, note = vc._validate_against_schema(bad, SCHEMA_REL)
        self.assertFalse(ok, note)


class SelfTest(unittest.TestCase):
    def test_selftest_passes(self):
        import io
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ml.selftest(), 0)


if __name__ == "__main__":
    unittest.main()
