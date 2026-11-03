#!/usr/bin/env python3
"""
Unit tests for scripts/dangling_dns.py -- recon-stage dangling-DNS classifier.

Regression focus: host-discovery must EMIT `asset:dangling-dns` when its dnsx CNAME/NS resolution
surfaces a takeover candidate, so the (non-baseline) subdomain-takeover executor is routed instead of
silently skipped ("no dangling DNS record surfaced"). The classifier is DNS-level triage; the executor
does the authoritative HTTP-fingerprint + claimability confirmation.

Stdlib only, runnable as `python test_dangling_dns.py` (the CI convention).
"""
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import dangling_dns as dd  # noqa: E402


class SuffixMatch(unittest.TestCase):
    def test_known_services(self):
        self.assertEqual(dd.match_service("app.herokuapp.com"), "Heroku")
        self.assertEqual(dd.match_service("x.y.github.io"), "GitHub Pages")

    def test_longest_suffix_wins(self):
        self.assertEqual(dd.match_service("b.s3.amazonaws.com"), "AWS S3")  # not the shorter "AWS"

    def test_case_and_trailing_dot(self):
        self.assertEqual(dd.match_service("App.Github.IO."), "GitHub Pages")

    def test_unknown_is_none(self):
        self.assertIsNone(dd.match_service("lb.internal.example.com"))


class Classify(unittest.TestCase):
    def test_known_service_resolving_is_candidate(self):
        # "resolves" != "claimed" — a github.io CNAME is a candidate even when it resolves.
        r = dd.classify([{"subdomain": "d.t.com", "record_type": "CNAME",
                          "target": "t.github.io", "target_resolves": True}])
        self.assertTrue(r["emit"])
        self.assertEqual(r["candidates"][0]["confidence"], "medium")
        self.assertEqual(r["candidates"][0]["service"], "GitHub Pages")

    def test_nxdomain_known_service_is_high(self):
        r = dd.classify([{"subdomain": "c.t.com", "record_type": "CNAME",
                          "target": "old.herokuapp.com", "target_resolves": False}])
        self.assertEqual(r["candidates"][0]["confidence"], "high")

    def test_dangling_cname_unknown_target_is_candidate(self):
        r = dd.classify([{"subdomain": "l.t.com", "record_type": "CNAME",
                          "target": "gone.vendor.net", "target_resolves": False}])
        self.assertEqual(r["candidates"][0]["confidence"], "medium")
        self.assertIsNone(r["candidates"][0]["service"])

    def test_dangling_ns_is_high(self):
        r = dd.classify([{"subdomain": "z.t.com", "record_type": "NS",
                          "target": "ns1.dead.net", "target_resolves": False}])
        self.assertEqual(r["candidates"][0]["record_type"], "NS")
        self.assertEqual(r["candidates"][0]["confidence"], "high")

    def test_wildcard_is_skipped_not_candidate(self):
        r = dd.classify([{"subdomain": "*.t.com", "record_type": "CNAME",
                          "target": "x.github.io", "target_resolves": True, "is_wildcard": True}])
        self.assertEqual(r["candidates"], [])
        self.assertEqual(r["skipped_wildcards"], ["*.t.com"])
        self.assertFalse(r["emit"])

    def test_inhouse_resolving_cname_is_not_a_candidate(self):
        r = dd.classify([{"subdomain": "app.t.com", "record_type": "CNAME",
                          "target": "lb.t.com", "target_resolves": True}])
        self.assertFalse(r["emit"])
        self.assertEqual(r["candidates"], [])

    def test_emit_signal_only_when_candidates(self):
        self.assertEqual(dd.classify([])["signals"], [])
        hit = dd.classify([{"subdomain": "c.t.com", "record_type": "CNAME",
                            "target": "old.herokuapp.com", "target_resolves": False}])
        self.assertEqual(hit["signals"], [dd.SIGNAL])


class SelfTest(unittest.TestCase):
    def test_module_selftest(self):
        dd.selftest()


if __name__ == "__main__":
    unittest.main()
