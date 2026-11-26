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
ROUTING_PATH = CONTRACT / "routing-map.json"
STRAT = ROOT / "skills" / "strategist"
REDSTRIKE_SKILL = ROOT / ".claude" / "skills" / "redstrike" / "SKILL.md"


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


# ---------------------------------------------------------------------------
# L-E: session_dependence routing + strategist dead-session auto-reorder
# ---------------------------------------------------------------------------

# The documented reorder rule (mirrors skills/strategist/SKILL.md "Session-dependence-aware ordering").
# A reference implementation so the test proves the rule is well-defined, schema-supported, and
# self-consistent with the routing-map partition — the strategist itself is an LLM-driven skill.
_INDEP, _DEP, _MIXED = "independent", "dependent", "mixed"
_DEAD_STATES = {"expiring", "expired", "dead"}
_NO_REORDER_STATES = {"live", "unknown"}


def _band(dep):
    """Band index for the dead-session front-load: independent(0) < mixed/absent(1) < dependent(2)."""
    return {_INDEP: 0, _MIXED: 1, _DEP: 2}.get(dep or _MIXED, 1)


def plan_for_session(classes, session_status):
    """Reference strategist output for a set of (class, session_dependence, value_rank) tuples under a
    given aggregate session_status. ORDER + ANNOTATION only: never drops/skips a class, never a ledger.
    `classes` = list of dicts {class, dep, value} where `value` is the value-only priority (lower first)."""
    dead = session_status in _DEAD_STATES
    if dead:
        ordered = sorted(classes, key=lambda c: (_band(c["dep"]), c["value"]))
    else:  # live / unknown / absent -> value order, no reorder
        ordered = sorted(classes, key=lambda c: c["value"])
    queue = []
    for i, c in enumerate(ordered, start=1):
        entry = {
            "rank": i, "class": c["class"], "queue_state": "queued",
            "session_dependence": c["dep"],
            "depth_budget": {"tier": "floor"},
            "rationale": f"{c['class']} ranked by session={session_status}",
        }
        if dead and c["dep"] == _DEP:
            entry["needs"] = ["fresh-session"]
        queue.append(entry)
    plan = {
        "version": 1, "engagement": "acme-2026-11", "generated_at": "2026-11-26T00:00:00Z",
        "iteration": 0, "ledger_owner": "coverage.py", "queue": queue,
    }
    if session_status != "absent":
        plan["session_state"] = {"status": session_status, "source": "runtime/session_status.json",
                                 "needs_recapture": 2 if dead else 0}
    return plan


class RoutingSessionDependence(unittest.TestCase):
    """routing-map.json carries an additive, optional, correctly-partitioned session_dependence field."""

    def setUp(self):
        self.rmap = json.loads(ROUTING_PATH.read_text(encoding="utf-8"))
        self.cats = {c["id"]: c for c in self.rmap["categories"]}

    def test_values_in_enum_when_present(self):
        for cid, c in self.cats.items():
            if "session_dependence" in c:
                self.assertIn(c["session_dependence"], (_INDEP, _DEP, _MIXED),
                              f"{cid}: session_dependence out of enum")

    def test_field_is_optional_backward_compatible(self):
        # non-web/non-capability phases are intentionally left ABSENT (=> mixed/unknown default)
        absent = [cid for cid, c in self.cats.items() if "session_dependence" not in c]
        self.assertTrue(absent, "the field must be optional — some categories stay absent (backward-compat)")

    def test_independent_classes_assigned(self):
        for cid in ("auth", "cve-intelligence", "exposed-surface", "security-headers", "tls-attacks",
                    "cors", "clickjacking", "open-redirect", "crlf-injection", "cache-poisoning",
                    "host-header", "subdomain-takeover"):
            self.assertEqual(self.cats[cid].get("session_dependence"), _INDEP,
                             f"{cid} must be session-independent (forge/unauth — runs with a dead session)")

    def test_dependent_classes_assigned(self):
        for cid in ("authz", "api", "file", "business-logic", "race-condition"):
            self.assertEqual(self.cats[cid].get("session_dependence"), _DEP,
                             f"{cid} must be session-dependent (needs a live user session)")

    def test_no_new_validate_break_shape(self):
        # the field never appears on a category that lacks an id (sanity: it rides on real categories)
        for c in self.rmap["categories"]:
            if "session_dependence" in c:
                self.assertIn("id", c)


class SessionAwareSchema(unittest.TestCase):
    """hunt_plan.schema.json gained the optional session_state / entry.needs / entry.session_dependence."""

    def setUp(self):
        self.vc = _load_vc()
        self.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def _errs(self, doc):
        return self.vc._stdlib_schema_errors(doc, self.schema)

    def test_schema_declares_session_state_closed(self):
        ss = self.schema["$defs"]["session_state"]
        self.assertIs(ss.get("additionalProperties"), False, "session_state must be a closed object")
        self.assertEqual(ss["properties"]["status"]["enum"],
                         ["live", "expiring", "expired", "dead", "unknown"])

    def test_schema_declares_needs_and_session_dependence(self):
        ep = self.schema["$defs"]["entry"]["properties"]
        self.assertEqual(ep["needs"]["items"]["enum"], ["fresh-session"])
        self.assertEqual(ep["session_dependence"]["enum"], [_INDEP, _DEP, _MIXED])
        # they are OPTIONAL (not newly required) — backward-compatible
        self.assertNotIn("needs", self.schema["$defs"]["entry"]["required"])
        self.assertNotIn("session_dependence", self.schema["$defs"]["entry"]["required"])
        self.assertNotIn("session_state", self.schema.get("required", []))

    def test_old_plan_without_new_fields_still_validates(self):
        self.assertEqual(self._errs(_valid_plan()), [],
                         "a pre-L-E hunt_plan (no session fields) must still validate — additive only")

    def test_dead_session_plan_validates(self):
        classes = [
            {"class": "auth", "dep": _INDEP, "value": 3},
            {"class": "cve-intelligence", "dep": _INDEP, "value": 5},
            {"class": "xss", "dep": _MIXED, "value": 1},
            {"class": "idor", "dep": _DEP, "value": 2},
            {"class": "business-logic", "dep": _DEP, "value": 4},
        ]
        plan = plan_for_session(classes, "dead")
        self.assertEqual(self._errs(plan), [], "a dead-session reordered plan must validate clean")

    def test_bad_session_status_rejected(self):
        plan = plan_for_session([{"class": "auth", "dep": _INDEP, "value": 1}], "dead")
        plan["session_state"]["status"] = "stale"
        self.assertTrue(self._errs(plan), "an off-enum session_state.status must be rejected")

    def test_bad_needs_value_rejected(self):
        plan = plan_for_session([{"class": "idor", "dep": _DEP, "value": 1}], "dead")
        plan["queue"][0]["needs"] = ["re-auth"]
        self.assertTrue(self._errs(plan), "an off-enum needs annotation must be rejected")

    def test_session_state_closed_rejects_extra(self):
        plan = plan_for_session([{"class": "auth", "dep": _INDEP, "value": 1}], "dead")
        plan["session_state"]["forced"] = True
        self.assertTrue(self._errs(plan), "session_state is a closed object — stray keys rejected")


class DeadSessionReorder(unittest.TestCase):
    """The documented reorder behavior: front-load independent, annotate dependent, drop NOTHING."""

    def _classes(self):
        # built so VALUE order would interleave independent/dependent — proving the reorder, not luck
        return [
            {"class": "idor", "dep": _DEP, "value": 1},            # highest value but session-dependent
            {"class": "xss", "dep": _MIXED, "value": 2},
            {"class": "auth", "dep": _INDEP, "value": 3},
            {"class": "business-logic", "dep": _DEP, "value": 4},
            {"class": "cve-intelligence", "dep": _INDEP, "value": 5},
            {"class": "exposed-surface", "dep": _INDEP, "value": 6},
        ]

    def test_dead_session_fronts_independent_before_dependent(self):
        plan = plan_for_session(self._classes(), "dead")
        ranks = {e["class"]: e["rank"] for e in plan["queue"]}
        last_indep = max(ranks[c["class"]] for c in self._classes() if c["dep"] == _INDEP)
        first_dep = min(ranks[c["class"]] for c in self._classes() if c["dep"] == _DEP)
        self.assertLess(last_indep, first_dep,
                        "every session-independent class must rank ahead of every dependent one on a dead session")

    def test_dependent_queue_annotated_needs_fresh_session(self):
        plan = plan_for_session(self._classes(), "dead")
        for e in plan["queue"]:
            if e["session_dependence"] == _DEP:
                self.assertEqual(e.get("needs"), ["fresh-session"],
                                 f"{e['class']} (dependent) must be annotated needs:fresh-session on a dead session")
            else:
                self.assertNotIn("needs", e, f"{e['class']} (non-dependent) must NOT carry the annotation")

    def test_invariant_no_class_dropped_or_skipped(self):
        src = {c["class"] for c in self._classes()}
        plan = plan_for_session(self._classes(), "dead")
        got = {e["class"] for e in plan["queue"]}
        self.assertEqual(src, got, "INVARIANT: the reorder drops NO class — every input class is still queued")
        for e in plan["queue"]:
            self.assertEqual(e["queue_state"], "queued",
                             "INVARIANT: no class is marked skipped — a dead session reorders, it does not skip")

    def test_invariant_no_ledger_written(self):
        plan = plan_for_session(self._classes(), "dead")
        self.assertEqual(plan["ledger_owner"], "coverage.py",
                         "INVARIANT: coverage.py stays the sole ledger owner; the strategist writes no ledger")
        # the plan carries no coverage-ledger fields (status/signals_used) — it is a pure ranking artifact
        for key in ("status", "signals_used", "coverage"):
            self.assertNotIn(key, plan)

    def test_live_session_order_unchanged(self):
        plan = plan_for_session(self._classes(), "live")
        # value order preserved: idor(1) ranks first because the session is live — no front-load
        self.assertEqual(plan["queue"][0]["class"], "idor")
        self.assertTrue(all("needs" not in e for e in plan["queue"]),
                        "a live session carries NO needs:fresh-session annotations")

    def test_unknown_session_is_recall_safe_no_reorder(self):
        plan = plan_for_session(self._classes(), "unknown")
        self.assertEqual(plan["queue"][0]["class"], "idor",
                         "unknown session must behave like live (no reorder) — a missing signal never shrinks the hunt")
        self.assertTrue(all("needs" not in e for e in plan["queue"]))

    def test_reorder_uses_real_routing_map_partition(self):
        # cross-check the reference rule against the SHIPPED routing-map partition for a realistic set
        rmap = json.loads(ROUTING_PATH.read_text(encoding="utf-8"))
        cats = {c["id"]: c for c in rmap["categories"]}
        sample = ["authz", "auth", "business-logic", "cve-intelligence", "exposed-surface", "api"]
        classes = [{"class": cid, "dep": cats[cid].get("session_dependence", _MIXED), "value": i}
                   for i, cid in enumerate(sample)]
        plan = plan_for_session(classes, "expired")
        ranks = {e["class"]: e["rank"] for e in plan["queue"]}
        # auth/cve/exposed are independent -> must all precede idor/api/business-logic (dependent)
        indep = [c for c in sample if cats[c].get("session_dependence") == _INDEP]
        dep = [c for c in sample if cats[c].get("session_dependence") == _DEP]
        self.assertTrue(max(ranks[c] for c in indep) < min(ranks[c] for c in dep),
                        "shipped routing-map partition must front-load real independent classes over dependent ones")


class SessionWiringDocs(unittest.TestCase):
    def test_strategist_skill_documents_session_dependence(self):
        text = (STRAT / "SKILL.md").read_text(encoding="utf-8").lower()
        for needle in ("session_dependence", "session-independent", "needs: fresh-session",
                       "session_status.json", "front-load"):
            self.assertIn(needle, text, f"strategist SKILL.md must document '{needle}'")

    def test_orchestrator_skill_wires_the_front_load(self):
        if not REDSTRIKE_SKILL.is_file():
            self.skipTest("redstrike orchestrator SKILL.md not present in this checkout")
        text = REDSTRIKE_SKILL.read_text(encoding="utf-8").lower()
        self.assertIn("session_dependence", text)
        self.assertIn("needs: fresh-session", text)
        self.assertIn("session status", text)


if __name__ == "__main__":
    unittest.main()
