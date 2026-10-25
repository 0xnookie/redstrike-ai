#!/usr/bin/env python3
"""
Unit tests for scripts/coverage.py signal loading + deterministic routing.

Regression focus: `_load_signals` must accept the NESTED document the Redstrike
signals feeder emits — {"signals": [...], "signal_evidence": {...}, ...} — and use
its inner `signals` list, NOT the top-level keys. The old code took the top-level
keys of any dict as the signal set, so the feeder's documented shape silently
collapsed routing to baseline-only with no error.

Stdlib only, runnable as `python test_coverage.py` (the CI convention).
"""
import json
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import coverage as c  # noqa: E402


def _write(tmp, obj):
    p = pathlib.Path(tmp) / "signals.json"
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


class LoadSignals(unittest.TestCase):
    def test_bare_list(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(
                c._load_signals(_write(t, ["tech:wordpress", "param:injectable"])),
                {"tech:wordpress", "param:injectable"},
            )

    def test_flat_object_truthy(self):
        with tempfile.TemporaryDirectory() as t:
            got = c._load_signals(_write(t, {"tech:wordpress": True, "param:any": False}))
            self.assertEqual(got, {"tech:wordpress"})

    def test_nested_feeder_document(self):
        """THE regression: a feeder-shaped doc must yield its inner signals,
        never the wrapper keys ('signals', 'signal_evidence', ...)."""
        doc = {
            "_comment": "recon signals",
            "signals": ["tech:wordpress", "endpoint:api", "param:injectable"],
            "signal_evidence": {"tech:wordpress": "generator meta"},
            "surfaces_ruled_out": {"endpoint:https": "plain http"},
            "phases": ["web"],
        }
        with tempfile.TemporaryDirectory() as t:
            got = c._load_signals(_write(t, doc))
        self.assertEqual(got, {"tech:wordpress", "endpoint:api", "param:injectable"})
        # the wrapper keys must NOT leak in as signals
        for junk in ("signals", "signal_evidence", "surfaces_ruled_out", "phases", "_comment"):
            self.assertNotIn(junk, got)

    def test_nested_signals_as_object(self):
        doc = {"signals": {"tech:wordpress": True, "flow:auth": True, "x": False}}
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(
                c._load_signals(_write(t, doc)), {"tech:wordpress", "flow:auth"}
            )

    def test_flat_object_drops_meta_keys(self):
        """A mistakenly-flat feeder doc can't smuggle metadata keys in as signals."""
        doc = {"_comment": "x", "signal_evidence": {"a": 1}, "tech:wordpress": True}
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(c._load_signals(_write(t, doc)), {"tech:wordpress"})

    def test_none_is_recall_safe(self):
        self.assertIsNone(c._load_signals(None))


class RoutingFromNestedDoc(unittest.TestCase):
    """End-to-end: the nested doc must route exactly like the equivalent bare list,
    and must NOT collapse to baseline-only (the symptom of the bug)."""

    @classmethod
    def setUpClass(cls):
        cls.m = c.load_map()

    def _plan_ids(self, signals):
        led = c.plan(self.m, signals, {"web"})
        return {x["id"]: x["status"] for x in led["categories"]}

    def test_nested_equals_bare_list(self):
        sigs = ["tech:wordpress", "param:injectable", "endpoint:api",
                "objref:enumerable", "identities:multi"]
        doc = {"signals": sigs, "signal_evidence": {}, "phases": ["web"]}
        with tempfile.TemporaryDirectory() as t:
            from_doc = c._load_signals(_write(t, doc))
            from_list = c._load_signals(_write(t, sigs))
        self.assertEqual(from_doc, from_list)
        self.assertEqual(self._plan_ids(from_doc), self._plan_ids(from_list))

    def test_nested_doc_does_not_collapse_to_baseline(self):
        # With real signals, triggered non-baseline categories must be pending,
        # and untriggered ones skipped — NOT the all-skipped-but-baseline collapse.
        doc = {"signals": ["tech:wordpress", "param:injectable", "param:search"]}
        with tempfile.TemporaryDirectory() as t:
            sigs = c._load_signals(_write(t, doc))
        ids = self._plan_ids(sigs)
        self.assertEqual(ids.get("framework-wordpress"), "pending")  # tech:wordpress
        self.assertEqual(ids.get("sqli"), "pending")                 # param:injectable/search
        self.assertEqual(ids.get("ssrf"), "skipped")                 # no url-fetching signal
        # baseline still pending regardless
        self.assertEqual(ids.get("secrets"), "pending")

    def test_buggy_behaviour_would_have_collapsed(self):
        """Guard: feeding the wrapper KEYS (the old bug) routes nothing but baseline —
        proving the fix (using the inner list) is what prevents the collapse."""
        wrapper_keys = {"signals", "signal_evidence", "surfaces_ruled_out", "phases"}
        ids = self._plan_ids(wrapper_keys)
        self.assertEqual(ids.get("framework-wordpress"), "skipped")  # tech:wordpress NOT seen
        self.assertEqual(ids.get("sqli"), "skipped")


class SelfTest(unittest.TestCase):
    def test_coverage_selftest_passes(self):
        self.assertEqual(c.selftest(), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
