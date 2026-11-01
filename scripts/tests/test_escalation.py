#!/usr/bin/env python3
"""
Unit tests for scripts/escalation.py -- the empty-class escalation ladder (recall fix #3).

Core guarantee: a class that returns 0 findings on a HIGH-prior surface must not be accepted as
clean until its escalation ladder is exhausted; the ladders encode the exact escalations that
unblocked findings in the juice-shop recall run (SQLi column-derive, XSS browser-render, JWT
cookie+header). Low-prior empties stay acceptable; unknown prior is conservative (recall-safe).

Stdlib only, runnable as `python test_escalation.py` (the CI convention).
"""
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import escalation as esc  # noqa: E402


class Assess(unittest.TestCase):
    def test_found_short_circuits(self):
        self.assertEqual(esc.assess("sqli", 3, "high")["verdict"], "found")

    def test_high_prior_empty_must_escalate(self):
        a = esc.assess("sqli", 0, "high")
        self.assertEqual(a["verdict"], "escalate")
        self.assertTrue(a["remaining"])

    def test_sqli_leads_with_derive_not_assume(self):
        # The 10-column lesson: never accept a capped UNION guess as clean.
        self.assertEqual(esc.assess("sqli", 0, "high")["remaining"][0], "derive-not-assume")

    def test_xss_leads_with_browser_render(self):
        self.assertEqual(esc.assess("xss-dom", 0, "high")["remaining"][0], "browser-render")

    def test_jwt_leads_with_cookie_and_header(self):
        self.assertEqual(esc.assess("jwt", 0, "high")["remaining"][0], "token-cookie-and-header")

    def test_low_prior_empty_is_clear(self):
        self.assertEqual(esc.assess("open-redirect", 0, "low")["verdict"], "clear-ok")

    def test_unknown_prior_is_conservative(self):
        self.assertEqual(esc.assess("sqli", 0, "unknown")["verdict"], "escalate")

    def test_exhausted_ladder_is_honest_clear(self):
        full = esc.ladder_for("sqli")
        self.assertEqual(esc.assess("sqli", 0, "high", escalations_done=full)["verdict"],
                         "clear-after-escalation")

    def test_partial_progress_still_escalates_the_rest(self):
        a = esc.assess("sqli", 0, "high", escalations_done=["derive-not-assume"])
        self.assertEqual(a["verdict"], "escalate")
        self.assertNotIn("derive-not-assume", a["remaining"])


class BlockerPromotion(unittest.TestCase):
    def test_waf_blocker_promotes_waf_bypass(self):
        self.assertEqual(esc.assess("sqli", 0, "high", blockers=["waf"])["remaining"][0], "waf-bypass")

    def test_client_sanitizer_promotes_api_bypass(self):
        self.assertEqual(esc.assess("xss", 0, "high", blockers=["client-sanitizer"])["remaining"][0],
                         "api-inject-bypass-client")

    def test_header_only_token_promotes_cookie_and_header(self):
        self.assertEqual(esc.ladder_for("jwt", blockers=["header-only-token"])[0],
                         "token-cookie-and-header")


class FamilyResolution(unittest.TestCase):
    def test_exact_and_keyword_and_default(self):
        self.assertEqual(esc.family_for("nosql-injection"), "sqli")
        self.assertEqual(esc.family_for("something-xss-weird"), "xss")
        self.assertEqual(esc.family_for("bola-bfla"), "authz")
        self.assertEqual(esc.family_for("brand-new-class"), "generic")

    def test_needs_escalation_helper(self):
        self.assertTrue(esc.needs_escalation("sqli", 0, "high"))
        self.assertFalse(esc.needs_escalation("sqli", 2, "high"))
        self.assertFalse(esc.needs_escalation("open-redirect", 0, "low"))


class SelfTest(unittest.TestCase):
    def test_module_selftest(self):
        esc.selftest()


if __name__ == "__main__":
    unittest.main()
