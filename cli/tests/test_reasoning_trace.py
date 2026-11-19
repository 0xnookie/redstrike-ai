import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # cli/

from redstrike_cli import reasoning_trace as rt  # noqa: E402


SCOPE = {"engagement": "acme-2026", "target": "acme.com",
         "in_scope": {"domains": ["acme.com"]}, "notes": "Assess acme.com for vulnerabilities"}

COVERAGE = {"categories": [
    {"id": "idor", "name": "IDOR", "status": "attempted", "findings_count": 1,
     "skills": ["authz-context", "idor"]},
    {"id": "xss", "name": "Cross-site scripting", "status": "attempted", "findings_count": 0,
     "reason": "No reflection; no executing DOM sink.", "skills": ["xss-context", "xss-reflected"]},
    {"id": "sqli", "name": "SQL injection", "status": "pending", "findings_count": 0,
     "skills": ["sqli-inband"]},
]}

FINDINGS = [{
    "id": "RS-2026-003",
    "title": "IDOR on /api/orders/{id}",
    "asset": "https://acme.com/api/orders/7",
    "severity": "high",
    "status": "verified",
    "evidence": [{"type": "request_response", "ref": "idor/evidence/orders.txt"}],
    "reproduction": ["GET /api/orders/7 as user A returns user B's order."],
    "review": {"verdict": "accepted", "reviewer": "idor-verify"},
}]


class TestBuildTrace(unittest.TestCase):
    def setUp(self):
        self.doc = rt.build_trace(SCOPE, COVERAGE, FINDINGS)
        self.by_id = {n["id"]: n for n in self.doc["nodes"]}
        self.edges = self.doc["edges"]

    def test_root_goal_present(self):
        self.assertIn("goal:root", self.by_id)
        self.assertEqual(self.by_id["goal:root"]["kind"], rt.GOAL)

    def test_finding_node_cross_references_existing_finding_id(self):
        node = self.by_id.get("finding:RS-2026-003")
        self.assertIsNotNone(node)
        self.assertEqual(node["kind"], rt.FINDING)
        # the CRITICAL contract: the finding node carries the EXISTING finding id verbatim
        self.assertEqual(node["finding_id"], "RS-2026-003")

    def test_full_provenance_chain_goal_intent_fact_finding(self):
        """goal --spawns--> intent --yields--> fact --proves--> finding, all edges present."""
        rels = {(e["source"], e["target"]): e["rel"] for e in self.edges}
        self.assertEqual(rels.get(("goal:root", "intent:idor")), rt.SPAWNS)
        self.assertEqual(rels.get(("intent:idor", "fact:RS-2026-003")), rt.YIELDS)
        self.assertEqual(rels.get(("fact:RS-2026-003", "finding:RS-2026-003")), rt.PROVES)

    def test_fact_keys_off_finding_id_and_carries_evidence_ref(self):
        fact = self.by_id.get("fact:RS-2026-003")
        self.assertIsNotNone(fact)
        self.assertEqual(fact["kind"], rt.FACT)
        self.assertEqual(fact["evidence_ref"], "idor/evidence/orders.txt")

    def test_ruled_out_hypothesis_gets_negative_fact(self):
        # xss was attempted with 0 findings + a reason → a ruled-out fact under its intent
        self.assertIn("intent:xss", self.by_id)
        ro = self.by_id.get("fact:ruledout:xss")
        self.assertIsNotNone(ro)
        self.assertTrue(ro["meta"]["ruled_out"])
        self.assertIn(("intent:xss", "fact:ruledout:xss"), {(e["source"], e["target"]) for e in self.edges})

    def test_pending_category_without_findings_is_not_an_intent(self):
        # sqli is pending + empty + no reason → no reasoning step recorded (honest: nothing explored)
        self.assertNotIn("intent:sqli", self.by_id)

    def test_every_edge_endpoint_resolves_to_a_node(self):
        ids = set(self.by_id)
        for e in self.edges:
            self.assertIn(e["source"], ids)
            self.assertIn(e["target"], ids)

    def test_deterministic(self):
        again = rt.build_trace(SCOPE, COVERAGE, FINDINGS)
        self.assertEqual(self.doc["nodes"], again["nodes"])
        self.assertEqual(self.doc["edges"], again["edges"])


class TestProducerSlug(unittest.TestCase):
    def test_strips_verify_and_prefix(self):
        self.assertEqual(rt.producer_of({"review": {"reviewer": "redstrike-idor-verify"}}), "idor")
        self.assertEqual(rt.producer_of({"review": {"reviewer": "xss-stored-verify"}}), "xss-stored")
        self.assertIsNone(rt.producer_of({"review": {}}))
        self.assertIsNone(rt.producer_of({}))


class TestResilience(unittest.TestCase):
    def test_empty_inputs_yield_just_the_goal(self):
        doc = rt.build_trace(None, None, None)
        self.assertEqual([n["kind"] for n in doc["nodes"]], [rt.GOAL])
        self.assertEqual(doc["edges"], [])

    def test_malformed_rows_are_skipped_not_fatal(self):
        doc = rt.build_trace(SCOPE, {"categories": ["nope", {"no_id": 1}]},
                             ["nope", {"no_id": True}, {"id": "RS-1", "review": {"reviewer": "idor-verify"}}])
        # the one real finding still resolves; the junk rows are dropped
        self.assertIn("finding:RS-1", {n["id"] for n in doc["nodes"]})


class TestAssembleAndWrite(unittest.TestCase):
    def test_assemble_discovers_per_skill_findings_and_writes_atomically(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "runtime").mkdir()
            (eng / "runtime" / "scope.json").write_text(json.dumps(SCOPE), encoding="utf-8")
            (eng / "coverage_ledger.json").write_text(json.dumps(COVERAGE), encoding="utf-8")
            (eng / "idor").mkdir()
            (eng / "idor" / "findings.json").write_text(json.dumps(FINDINGS), encoding="utf-8")

            doc = rt.assemble(eng)
            self.assertEqual(doc["engagement"], "acme-2026")
            self.assertIn("generated_at", doc)
            self.assertIn("finding:RS-2026-003", {n["id"] for n in doc["nodes"]})

            path = rt.write(eng, doc)
            self.assertTrue(path.is_file())
            self.assertFalse((eng / "runtime" / "reasoning_trace.json.tmp").exists())
            reloaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(reloaded["version"], rt.TRACE_SCHEMA_VERSION)


if __name__ == "__main__":
    unittest.main()
