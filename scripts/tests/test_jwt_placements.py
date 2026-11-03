#!/usr/bin/env python3
"""
Unit tests for scripts/jwt_placements.py -- deterministic forged-JWT carrier enumeration.

Regression focus: the JWT executor must send a forged / tampered token in BOTH a header
carrier AND a cookie carrier before it may conclude "not accepted". The anchoring case is
OWASP Juice Shop v20.3.0: a forged `alg:none` token in `Authorization: Bearer` did NOT trip
the Unsigned-JWT challenge, but the SAME token in the `token` cookie did. A header-only
confirmation is a silent false negative for every cookie-reading app.

Stdlib only, runnable as `python test_jwt_placements.py` (the CI convention).
"""
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import jwt_placements as jp  # noqa: E402


class MandatoryCore(unittest.TestCase):
    def test_core_spans_header_and_cookie(self):
        self.assertTrue(jp.spans_header_and_cookie(jp.MANDATORY))

    def test_core_is_bearer_header_plus_token_cookie(self):
        header = [p for p in jp.MANDATORY if p.kind == "header"][0]
        cookie = [p for p in jp.MANDATORY if p.kind == "cookie"][0]
        self.assertEqual((header.name, header.scheme), ("Authorization", "Bearer"))
        self.assertEqual(cookie.name, "token")  # the Juice Shop live case

    def test_enumeration_leads_with_the_core(self):
        places = jp.enumerate_placements()
        self.assertEqual((places[0].kind, places[0].name), ("header", "Authorization"))
        self.assertTrue(jp.spans_header_and_cookie(places))


class ConfirmationCompleteness(unittest.TestCase):
    def test_header_only_is_incomplete_regression(self):
        # The exact live false negative: Authorization-header-only must NOT be "ruled out".
        header_only = [jp.MANDATORY[0]]
        self.assertFalse(jp.confirmation_complete(header_only))
        miss = jp.missing_mandatory(header_only)
        self.assertEqual([(m.kind, m.name) for m in miss], [("cookie", "token")])

    def test_cookie_only_is_incomplete(self):
        # Symmetric gap: a header-reading app is missed by a cookie-only send.
        cookie_only = [jp.MANDATORY[1]]
        self.assertFalse(jp.confirmation_complete(cookie_only))
        self.assertEqual(jp.missing_mandatory(cookie_only)[0].kind, "header")

    def test_header_plus_cookie_is_complete(self):
        self.assertTrue(jp.confirmation_complete(list(jp.MANDATORY)))
        self.assertTrue(jp.confirmation_complete(jp.enumerate_placements()))

    def test_empty_send_is_incomplete(self):
        self.assertFalse(jp.confirmation_complete([]))
        self.assertEqual(len(jp.missing_mandatory([])), 2)


class Enumeration(unittest.TestCase):
    def test_dedup_observed_against_core_case_insensitive(self):
        observed = [
            jp.Placement("header", "authorization", scheme="Bearer", source="observed"),
            jp.Placement("cookie", "token", source="observed"),
            jp.Placement("cookie", "sessionJwt", source="observed"),
        ]
        enr = jp.enumerate_placements(observed=observed, include_defaults=False)
        keys = [p.key() for p in enr]
        self.assertEqual(len(keys), len(set(keys)), "no duplicate carriers")
        self.assertIn(("cookie", "sessionjwt"), keys)

    def test_core_spelling_wins_over_observed_duplicate(self):
        observed = [jp.Placement("header", "authorization", scheme="", source="observed")]
        enr = jp.enumerate_placements(observed=observed, include_defaults=False)
        auth = [p for p in enr if p.key() == ("header", "authorization")][0]
        self.assertEqual(auth.name, "Authorization")
        self.assertEqual(auth.scheme, "Bearer")
        self.assertEqual(auth.source, "mandatory")

    def test_defaults_widen_but_stay_deduped_and_complete(self):
        wide = jp.enumerate_placements()
        keys = [p.key() for p in wide]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertIn(("cookie", "jwt"), keys)
        self.assertIn(("header", "x-access-token"), keys)
        self.assertTrue(jp.confirmation_complete(wide))

    def test_no_defaults_is_just_core_plus_observed(self):
        enr = jp.enumerate_placements(include_defaults=False)
        self.assertEqual([p.key() for p in enr], [p.key() for p in jp.MANDATORY])


class Render(unittest.TestCase):
    def test_bearer_header(self):
        self.assertEqual(jp.MANDATORY[0].render("T"), ("header", "Authorization: Bearer T"))

    def test_cookie(self):
        self.assertEqual(jp.MANDATORY[1].render("T"), ("cookie", "token=T"))

    def test_bare_custom_header(self):
        self.assertEqual(jp.Placement("header", "X-JWT").render("T"), ("header", "X-JWT: T"))

    def test_unknown_kind_raises(self):
        with self.assertRaises(ValueError):
            jp.Placement("query", "jwt").render("T")


class SelfTest(unittest.TestCase):
    def test_module_selftest_passes(self):
        jp.selftest()  # raises on failure


if __name__ == "__main__":
    unittest.main()
