#!/usr/bin/env python3
"""
Unit tests for scripts/surface.py -- the surface-coverage ledger (recall fix #5).

Guarantee: a surface element recon DISCOVERED but no executor TESTED (and that wasn't skipped with a
reason) is a recall gap — the leak category coverage cannot see (20 injectable params found, 2 tested,
"sqli: attempted, 0 findings" still reads clean). Routed elements start `discovered`; unroutable ones
are `n/a`; `tested`/reasoned-`skipped` clear.

Stdlib only, runnable as `python test_surface.py` (the CI convention).
"""
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import surface as sf  # noqa: E402


class Routing(unittest.TestCase):
    def test_param_routes_to_injection_and_more(self):
        r = sf.route_surface("param")
        self.assertIn("sqli", r)
        self.assertIn("xss", r)

    def test_identity_routes_to_authz(self):
        self.assertEqual(sf.route_surface("identity"), ["authz", "api"])

    def test_unknown_kind_routes_nowhere(self):
        self.assertEqual(sf.route_surface("mystery"), [])


class PlanAndValidate(unittest.TestCase):
    def _plan(self):
        return sf.plan_from_items("demo", [
            {"kind": "param", "value": "q", "discovered_by": "content-discovery"},
            {"kind": "param", "value": "q"},            # duplicate -> dropped
            {"kind": "identity", "value": "userA"},
            {"kind": "sink", "value": "x"},
        ])

    def test_plan_dedupes_and_routes(self):
        led = self._plan()
        self.assertEqual(len(led["surfaces"]), 3)
        q = next(s for s in led["surfaces"] if s["value"] == "q")
        self.assertEqual(q["status"], "discovered")
        self.assertTrue(q["routed_to"])

    def test_unroutable_is_na(self):
        led = sf.plan_from_items("demo", [{"kind": "weird", "value": "z"}])
        self.assertEqual(led["surfaces"][0]["status"], "n/a")
        self.assertTrue(led["surfaces"][0]["reason"])

    def test_discovered_routed_surface_is_a_gap(self):
        led = self._plan()
        ok, _l, msgs = sf.validate(led)
        self.assertFalse(ok)
        self.assertTrue(any("untested surface" in m for m in msgs))

    def test_tested_clears(self):
        led = self._plan()
        for s in led["surfaces"]:
            if s["status"] == "discovered":
                s["status"] = "tested"
        self.assertTrue(sf.validate(led)[0])

    def test_skipped_needs_reason(self):
        led = sf.plan_from_items("demo", [{"kind": "param", "value": "q"}])
        led["surfaces"][0]["status"] = "skipped"
        led["surfaces"][0]["reason"] = ""
        self.assertFalse(sf.validate(led)[0])
        led["surfaces"][0]["reason"] = "login param — auth class owns it"
        self.assertTrue(sf.validate(led)[0])

    def test_empty_ledger_lenient_but_strict_fails(self):
        self.assertTrue(sf.validate({"surfaces": []})[0])
        self.assertFalse(sf.validate({"surfaces": []}, strict=True)[0])


class SurfaceGaps(unittest.TestCase):
    def test_gaps_for_recall_audit(self):
        led = sf.plan_from_items("demo", [{"kind": "param", "value": "id"}])
        g = sf.surface_gaps(led)
        self.assertEqual(g[0]["type"], "untested-surface")
        self.assertEqual(g[0]["severity"], "high")

    def test_no_gap_once_tested(self):
        led = sf.plan_from_items("demo", [{"kind": "param", "value": "id"}])
        led["surfaces"][0]["status"] = "tested"
        self.assertEqual(sf.surface_gaps(led), [])


class MergeReplan(unittest.TestCase):
    """Universal emission: `--plan` must be idempotent — re-running preserves tested/skipped progress
    and adds only new elements, so recon can emit the ledger every run (and late feeders / the
    re-convergence loop can re-emit) without clobbering a mark."""

    def _tested_base(self):
        led = sf.plan_from_items("demo", [{"kind": "param", "value": "q"}, {"kind": "param", "value": "id"}])
        q = next(s for s in led["surfaces"] if s["value"] == "q")
        q["status"] = "tested"
        q.setdefault("consumed_by", []).append("sqli")
        return led

    def test_merge_preserves_progress_and_adds_new(self):
        led = self._tested_base()
        merged = sf.merge_plan(led, [
            {"kind": "param", "value": "q"},           # present -> untouched (stays tested)
            {"kind": "param", "value": "id"},          # present -> untouched
            {"kind": "identity", "value": "userB"},    # NEW
        ])
        self.assertEqual(merged["_last_merge_added"], 1)
        bv = {s["value"]: s for s in merged["surfaces"]}
        self.assertEqual(bv["q"]["status"], "tested")
        self.assertIn("sqli", bv["q"]["consumed_by"])
        self.assertEqual(bv["userB"]["status"], "discovered")
        self.assertEqual(len(merged["surfaces"]), 3)

    def test_merge_is_idempotent(self):
        led = self._tested_base()
        once = sf.merge_plan(led, [{"kind": "identity", "value": "userB"}])
        self.assertEqual(once["_last_merge_added"], 1)
        twice = sf.merge_plan(once, [{"kind": "identity", "value": "userB"}])
        self.assertEqual(twice["_last_merge_added"], 0)
        self.assertEqual(len(twice["surfaces"]), 3)


class SchemaConformance(unittest.TestCase):
    def test_planned_ledger_matches_schema_keys(self):
        import json
        schema = json.loads((HERE.parents[2] / "skills/_contract/surface_ledger.schema.json").read_text())
        allowed = set(schema["$defs"]["surface"]["properties"])
        led = sf.plan_from_items("demo", [{"kind": "param", "value": "q"}])
        for s in led["surfaces"]:
            self.assertTrue(set(s).issubset(allowed), set(s) - allowed)
        self.assertTrue(set(schema["$defs"]["surface"]["required"]).issubset(set(led["surfaces"][0])))


class SelfTest(unittest.TestCase):
    def test_module_selftest(self):
        sf.selftest()


if __name__ == "__main__":
    unittest.main()
