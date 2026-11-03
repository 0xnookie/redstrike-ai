#!/usr/bin/env python3
"""
Unit tests for scripts/reconverge.py -- finding -> recon re-convergence (recall fix #6).

Regression focus: surface DISCOVERED DURING the hunt (an SSRF reaching an internal host, an
auth bypass yielding a second identity, a config leak exposing new endpoints) must re-open the
classes it now routes to, and the engagement is only DONE at the fixpoint -- a pass that adds
nothing new. The loop must always terminate (monotone work-list).

Stdlib only, runnable as `python test_reconverge.py` (the CI convention).
"""
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import reconverge as rc  # noqa: E402

MAPC = [
    {"id": "xss", "phase": "web", "triggers": ["sink:html-reflect", "sink:dom", "param:any"]},
    {"id": "sqli", "phase": "web", "triggers": ["param:injectable"]},
    {"id": "ssrf", "phase": "web", "triggers": ["param:url-fetching"]},
    {"id": "cloud", "phase": "cloud", "triggers": ["asset:cloud"]},
    {"id": "authz", "phase": "web", "triggers": ["identity:multi"]},
    {"id": "exposed-surface", "phase": "web", "triggers": []},
]
MAPP = {"cloud": {"auto_on": "asset:cloud"}, "web3": {"auto_on": "asset:smart-contract"}}


def _trig(cid):
    return next((c["triggers"] for c in MAPC if c["id"] == cid), [])


class SignalDrivenReopen(unittest.TestCase):
    def test_new_signal_reopens_attempted_class(self):
        cats = [{"id": "ssrf", "status": "attempted", "triggers": _trig("ssrf")}]
        p = rc.reconverge(set(), set(), cats,
                          [{"source": "js", "signals": ["param:url-fetching"]}], MAPC, MAPP)
        self.assertEqual({r["id"] for r in p["reopen"]}, {"ssrf"})
        self.assertFalse(p["converged"])

    def test_new_identity_reopens_skipped_authz(self):
        cats = [{"id": "authz", "status": "skipped", "reason": "one identity", "triggers": _trig("authz")}]
        p = rc.reconverge(set(), set(), cats,
                          [{"source": "auth-bypass", "signals": ["identity:multi"]}], MAPC, MAPP)
        self.assertEqual([r["id"] for r in p["reopen"]], ["authz"])
        self.assertEqual(p["reopen"][0]["from_status"], "skipped")

    def test_pending_class_is_not_reopened(self):
        cats = [{"id": "sqli", "status": "pending", "triggers": _trig("sqli")}]
        p = rc.reconverge(set(), set(), cats, [{"signals": ["param:injectable"]}], MAPC, MAPP)
        self.assertEqual(p["reopen"], [])

    def test_already_seen_signal_is_no_delta(self):
        cats = [{"id": "ssrf", "status": "attempted", "triggers": _trig("ssrf")}]
        p = rc.reconverge({"param:url-fetching"}, set(), cats,
                          [{"signals": ["param:url-fetching"]}], MAPC, MAPP)
        self.assertTrue(p["converged"])
        self.assertEqual(p["reopen"], [])


class SurfaceDrivenReopen(unittest.TestCase):
    def test_new_endpoint_reopens_exposed_surface(self):
        cats = [{"id": "exposed-surface", "status": "attempted"}]
        p = rc.reconverge(set(), set(), cats,
                          [{"source": "ssrf", "surface": [{"kind": "endpoint", "value": "http://10.0.0.5/"}]}],
                          MAPC, MAPP)
        self.assertIn("exposed-surface", {r["id"] for r in p["reopen"]})
        self.assertEqual(len(p["added_surface"]), 1)

    def test_unrouted_surface_recorded_but_no_reopen(self):
        p = rc.reconverge(set(), set(), [{"id": "xss", "status": "attempted"}],
                          [{"surface": [{"kind": "weird-kind", "value": "x"}]}], MAPC, MAPP)
        self.assertTrue(p["added_surface_unrouted"])
        self.assertEqual(p["reopen"], [])
        self.assertFalse(p["converged"])


class ScopeSafety(unittest.TestCase):
    def test_out_of_phase_class_is_replan_candidate_not_reopened(self):
        cats = [{"id": "cloud", "status": "n/a", "reason": "cloud phase not in scope", "triggers": _trig("cloud")}]
        p = rc.reconverge(set(), set(), cats, [{"signals": ["asset:cloud"]}], MAPC, MAPP)
        self.assertEqual(p["reopen"], [])  # never auto-activate an out-of-scope phase
        self.assertEqual([c["id"] for c in p["replan_candidates"]], ["cloud"])
        self.assertIn("cloud", p["replan_phases"])


class Fixpoint(unittest.TestCase):
    def test_nothing_discovered_is_converged(self):
        cats = [{"id": "ssrf", "status": "attempted", "triggers": _trig("ssrf")}]
        self.assertTrue(rc.reconverge({"param:url-fetching"}, set(), cats, [], MAPC, MAPP)["converged"])

    def test_apply_then_reconverge_terminates(self):
        cats = [{"id": "ssrf", "status": "attempted", "triggers": _trig("ssrf")},
                {"id": "exposed-surface", "status": "attempted"}]
        obs = [{"source": "ssrf", "signals": ["param:url-fetching"],
                "surface": [{"kind": "endpoint", "value": "http://10.0.0.5/"}]}]
        p = rc.reconverge(set(), set(), cats, obs, MAPC, MAPP)
        self.assertFalse(p["converged"])
        cov = {"categories": [dict(c) for c in cats], "signals_used": []}
        surf = {"engagement": "demo", "surfaces": []}
        rc.apply_plan(cov, surf, p)
        # the applied ledger: reopened -> pending, signal seen, surface recorded
        ssrf = next(c for c in cov["categories"] if c["id"] == "ssrf")
        self.assertEqual(ssrf["status"], "pending")
        self.assertEqual(ssrf["reopened_rounds"], 1)
        self.assertIn("param:url-fetching", cov["signals_used"])
        self.assertTrue(surf["surfaces"])
        # a second pass over the SAME inbox now converges (the delta is empty)
        seen = set(cov["signals_used"])
        skeys = {(s["kind"], s["value"]) for s in surf["surfaces"]}
        applied = [{"id": c["id"], "status": c["status"], "triggers": _trig(c["id"])} for c in cov["categories"]]
        self.assertTrue(rc.reconverge(seen, skeys, applied, obs, MAPC, MAPP)["converged"])


class SelfTest(unittest.TestCase):
    def test_module_selftest_passes(self):
        rc.selftest()


if __name__ == "__main__":
    unittest.main()
