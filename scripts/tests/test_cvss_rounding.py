#!/usr/bin/env python3
"""
Unit tests for scripts/cvss.py version-aware rounding.

CVSS v3.1 introduced the explicit ceil-to-tenth `Roundup`; v3.0 rounds half-up to one decimal. The
module scores both, so a parsed `CVSS:3.0/...` vector must NOT be over-rounded by the 3.1 Roundup.
These tests pin that a 3.0 vector whose raw score sits just above a tenth boundary (~4.001) rounds
DOWN to 4.0, while the same metrics as 3.1 keep the Roundup value 4.1 — and that every existing 3.1
result is unchanged. Stdlib only, runnable as `python test_cvss_rounding.py` (the CI convention).
"""
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]                  # scripts/
sys.path.insert(0, str(SCRIPTS))

import cvss  # noqa: E402

# raw base score ~4.00089: 3.0 half-up -> 4.0, 3.1 Roundup -> 4.1 (the version-rounding divergence).
_DIVERGENT = "AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:N/A:N"


class TestVersionRounding(unittest.TestCase):
    def test_v30_rounds_half_up_not_ceil(self):
        score, _, version = cvss.score_vector("CVSS:3.0/" + _DIVERGENT)
        self.assertEqual(version, "3.0")
        self.assertEqual(score, 4.0)            # half-up: 4.001 -> 4.0 (NOT the 3.1 ceil to 4.1)

    def test_v31_keeps_roundup(self):
        score, _, version = cvss.score_vector("CVSS:3.1/" + _DIVERGENT)
        self.assertEqual(version, "3.1")
        self.assertEqual(score, 4.1)            # Roundup: smallest tenth >= 4.001 is 4.1

    def test_same_metrics_differ_only_by_version(self):
        s30, _, _ = cvss.score_vector("CVSS:3.0/" + _DIVERGENT)
        s31, _, _ = cvss.score_vector("CVSS:3.1/" + _DIVERGENT)
        self.assertEqual((s30, s31), (4.0, 4.1))

    def test_no_prefix_defaults_to_roundup(self):
        # an un-prefixed vector is treated as 3.1 (the default), so it keeps Roundup — unchanged behavior
        score, _, version = cvss.score_vector(_DIVERGENT)
        self.assertEqual((score, version), (4.1, "3.1"))


class TestRounders(unittest.TestCase):
    def test_round_half_up_ties_go_up(self):
        self.assertEqual(cvss._round_half_up(4.05), 4.1)   # tie -> up
        self.assertEqual(cvss._round_half_up(4.04999), 4.0)
        self.assertEqual(cvss._round_half_up(4.0001), 4.0)

    def test_roundup_is_ceil_to_tenth(self):
        self.assertEqual(cvss._roundup(4.0001), 4.1)       # any excess over a tenth rounds up
        self.assertEqual(cvss._roundup(4.0), 4.0)          # exact tenth is unchanged


class TestExistingResultsUnchanged(unittest.TestCase):
    def test_all_31_selftest_cases_hold(self):
        """Every pinned first.org 3.1 reference value is identical after the rounding branch."""
        for vec, want_score, want_rating in cvss._SELFTEST:
            score, rating, _ = cvss.score_vector(vec)
            self.assertAlmostEqual(score, want_score, places=9, msg=vec)
            self.assertEqual(rating, want_rating, msg=vec)


if __name__ == "__main__":
    unittest.main()
