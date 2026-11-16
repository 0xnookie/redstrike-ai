#!/usr/bin/env python3
"""
Unit tests for the strategist / hunt-planner agentic upgrade:
  - hunt_plan.schema.json is a valid, versioned, CLOSED ranking artifact whose shape ENFORCES the
    strategist invariant: no `skipped` queue-state (only coverage.py may skip) and a depth-budget whose
    lowest tier is the escalation `floor` (a budget can never encode a below-floor effort).
  - a well-formed hunt_plan validates; the invariant-violating variants (a `skipped` state, an extra
    root key, a missing required field) FAIL — proven against the same stdlib schema checker the
    mechanical gate (verify_completion.py) uses when `jsonschema` isn't installed.
  - the strategist skill is wired review-only (emits hunt_plan.json, NOT findings → no verify.md) with
    its review.md manifest declaring hunt_plan.json + the schema ref.

Stdlib only, runnable as `python test_strategist.py` (the CI convention).
"""
import importlib.util
import json
import pathlib
import re
import sys
import unittest

HERE = pathlib.Path(__file__).resolve()
ROOT = HERE.parents[2]
CONTRACT = ROOT / "skills" / "_contract"
SCHEMA_PATH = CONTRACT / "hunt_plan.schema.json"
STRAT = ROOT / "skills" / "strategist"


def _load_vc():
    """Load verify_completion.py by path (reuse its stdlib schema checker)."""
    spec = importlib.util.spec_from_file_location("rs_vc_strattest", CONTRACT / "verify_completion.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _valid_plan():
    return {
        "version": 1,
        "engagement": "acme-2026-11",
        "generated_at": "2026-11-16T00:00:00Z",
        "iteration": 0,
        "inputs_seen": ["coverage_ledger.json", "surface_ledger.json", "cve_intel.json"],
        "ledger_owner": "coverage.py",
        "queue": [
            {"rank": 1, "class": "xss", "phase": "web", "queue_state": "queued",
             "prior": "high", "surface_count": 7, "severity_ceiling": "high",
             "depth_budget": {"tier": "deep", "min_ladder_steps": 6, "diversity_pass": True,
                              "rationale": "confirmed reflection + CVE-matched component"},
             "rationale": "most surface + confirmed reflection => hunt first, deepest"},
            {"rank": 2, "class": "idor", "phase": "web", "queue_state": "queued",
             "depth_budget": {"tier": "floor"},
             "rationale": "two identities but no enumerable id signal yet => floor is enough above recon"},
        ],
        "notes": "initial post-recon ranking",
    }


class SchemaShape(unittest.TestCase):
    def setUp(self):
        self.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def test_valid_json_and_versioned_closed_root(self):
        self.assertIn("version", self.schema.get("properties", {}),
                      "hunt_plan schema must declare a root 'version' (drift guard)")
        self.assertIs(self.schema.get("additionalProperties"), False,
                      "root must be a closed object")
        for req in ("version", "engagement", "generated_at", "iteration", "queue"):
            self.assertIn(req, self.schema.get("required", []))

    def test_queue_state_has_no_skipped(self):
        enum = self.schema["$defs"]["entry"]["properties"]["queue_state"]["enum"]
        self.assertNotIn("skipped", enum,
                         "INVARIANT: the strategist can never skip a class; only coverage.py may")
        self.assertNotIn("n/a", enum)
        for expected in ("queued", "in-progress", "done", "deferred"):
            self.assertIn(expected, enum)

    def test_depth_budget_lowest_tier_is_floor(self):
        tiers = self.schema["$defs"]["depth_budget"]["properties"]["tier"]["enum"]
        self.assertEqual(tiers[0], "floor",
                         "INVARIANT: the lowest budget is still the full escalation floor")
        self.assertEqual(tiers, ["floor", "standard", "deep"])

    def test_ledger_owner_pinned_to_coverage(self):
        self.assertEqual(self.schema["properties"]["ledger_owner"].get("const"), "coverage.py",
                         "the strategist asserts coverage.py is the sole ledger owner")

    def test_entry_requires_depth_budget_and_rationale(self):
        req = self.schema["$defs"]["entry"]["required"]
        for k in ("rank", "class", "queue_state", "depth_budget", "rationale"):
            self.assertIn(k, req)


class SchemaValidation(unittest.TestCase):
    """Validate sample docs with the mechanical gate's own stdlib checker."""

    def setUp(self):
        self.vc = _load_vc()
        self.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def _errs(self, doc):
        return self.vc._stdlib_schema_errors(doc, self.schema)

    def test_valid_plan_passes(self):
        self.assertEqual(self._errs(_valid_plan()), [],
                         "a well-formed hunt_plan must validate clean")

    def test_skipped_queue_state_fails(self):
        bad = _valid_plan()
        bad["queue"][0]["queue_state"] = "skipped"
        errs = self._errs(bad)
        self.assertTrue(errs, "a 'skipped' queue-state must be rejected by the schema")
        self.assertTrue(any("not one of" in e for e in errs))

    def test_extra_root_key_fails(self):
        bad = _valid_plan()
        bad["signals_used"] = ["param:injectable"]  # a ledger-ish field the strategist must not add
        errs = self._errs(bad)
        self.assertTrue(any("unexpected property 'signals_used'" in e for e in errs),
                        "the closed root must reject stray keys")

    def test_missing_required_entry_field_fails(self):
        bad = _valid_plan()
        del bad["queue"][0]["rationale"]
        errs = self._errs(bad)
        self.assertTrue(any("missing required 'rationale'" in e for e in errs))

    def test_bad_depth_tier_fails(self):
        bad = _valid_plan()
        bad["queue"][1]["depth_budget"]["tier"] = "below-floor"
        errs = self._errs(bad)
        self.assertTrue(errs, "a tier outside floor/standard/deep must be rejected")


class SkillWiring(unittest.TestCase):
    def test_skill_files_present(self):
        for f in ("SKILL.md", "checklist.md", "review.md"):
            self.assertTrue((STRAT / f).is_file(), f"strategist missing {f}")

    def test_review_only_no_verify(self):
        self.assertFalse((STRAT / "verify.md").is_file(),
                         "strategist emits hunt_plan.json, not findings — it must stay review-only")

    def test_required_sections(self):
        text = (STRAT / "SKILL.md").read_text(encoding="utf-8")
        for h in ("## Interview", "## Goal", "## Phases", "## Safety"):
            self.assertIn(h, text)
        self.assertTrue("## Steps" in text or "## Orchestration" in text)

    def test_invariant_stated_prominently(self):
        text = (STRAT / "SKILL.md").read_text(encoding="utf-8").lower()
        self.assertIn("absolute invariant", text)
        self.assertIn("coverage.py", text)
        self.assertIn("never", text)

    def test_review_manifest_declares_schema(self):
        text = (STRAT / "review.md").read_text(encoding="utf-8")
        m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
        self.assertIsNotNone(m, "review.md must embed a JSON manifest")
        manifest = json.loads(m.group(1))
        arts = manifest.get("artifacts", [])
        self.assertTrue(
            any(a.get("path") == "hunt_plan.json"
                and a.get("schema") == "skills/_contract/hunt_plan.schema.json"
                for a in arts),
            "manifest must declare hunt_plan.json with the hunt_plan schema ref")
        self.assertFalse(any(a.get("path") == "findings.json" for a in arts),
                         "a planning skill must not declare findings.json")


if __name__ == "__main__":
    unittest.main()
