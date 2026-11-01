#!/usr/bin/env python3
"""
Unit tests for scripts/sqli_union.py -- deterministic UNION column-count derivation.

Regression focus: the SQLi executor must DERIVE the UNION column count with an open-ended
sweep, never assume it and never treat an error on a guessed count as "not injectable".

The anchoring case is OWASP Juice Shop v20.3.0 `/rest/products/search`: the Products table
has 10 columns (an `alternateImages` column was added), so a UNION guessing 9 -- or an
ORDER BY sweep capped at 9, as the old payload refs example literally wrote -- silently
misses it and loses the User Credentials + Database Schema findings.

Stdlib only, runnable as `python test_sqli_union.py` (the CI convention).
"""
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import sqli_union as su  # noqa: E402


class DeriveColumnCount(unittest.TestCase):
    def test_wide_range_exact(self):
        for c in [1, 2, 3, 5, 8, 9, 10, 13, 16, 17, 26, 50, 127, 300]:
            with self.subTest(columns=c):
                self.assertEqual(su.derive_column_count(lambda n, k=c: n <= k), c)

    def test_juice_shop_10_columns_regression(self):
        # The exact live case this fix exists for.
        self.assertEqual(su.derive_column_count(lambda n: n <= 10), 10)

    def test_old_capped_at_9_scan_would_miss_it(self):
        # Document the bug: a linear sweep that stops at 9 returns 9, not 10.
        true_count = 10
        capped = max((n for n in range(1, 10) if n <= true_count), default=0)
        self.assertEqual(capped, 9)
        self.assertNotEqual(capped, true_count)
        # The fixed helper does not have that ceiling.
        self.assertEqual(su.derive_column_count(lambda n: n <= true_count), true_count)

    def test_erroring_probe_marks_boundary_not_bail(self):
        # A probe that RAISES for n > count (a real SQL 500) must still yield the count when
        # the caller maps the exception to False -- an error is the boundary, not a dead end.
        def safe(n):
            try:
                if n > 10:
                    raise RuntimeError("SQLITE_ERROR: 1st ORDER BY term out of range")
                return True
            except RuntimeError:
                return False
        self.assertEqual(su.derive_column_count(safe), 10)

    def test_baseline_not_injectable_raises_not_clean(self):
        # ORDER BY 1 rejected => context/breakout problem => explicit error (open-proof-gap),
        # never a silent 0 / "clean" verdict.
        with self.assertRaises(su.ColumnCountError):
            su.derive_column_count(lambda n: False)

    def test_unbounded_probe_hits_safety_bound(self):
        with self.assertRaises(su.ColumnCountError):
            su.derive_column_count(lambda n: True, max_columns=64)

    def test_probe_count_is_logarithmic(self):
        # Guard efficiency: deriving a large count must stay O(log n), not O(n).
        calls = {"n": 0}

        def probe(n):
            calls["n"] += 1
            return n <= 300
        self.assertEqual(su.derive_column_count(probe), 300)
        self.assertLess(calls["n"], 40, "sweep should be logarithmic, not linear")


class ConfirmAndLocate(unittest.TestCase):
    def test_confirm_corroborates_right_count(self):
        self.assertTrue(su.confirm_column_count(lambda n: n == 10, 10))   # exact boundary
        self.assertTrue(su.confirm_column_count(lambda n: n <= 10, 10))   # 10 ok, 11 not -> boundary

    def test_confirm_rejects_undercount_and_wrong(self):
        self.assertFalse(su.confirm_column_count(lambda n: n <= 11, 10))  # 11 also ok => under-count tell
        self.assertFalse(su.confirm_column_count(lambda n: n == 9, 10))   # 10 not accepted at all

    def test_string_column_index(self):
        self.assertEqual(su.string_column_index(lambda c, i: i == 1, 10), 1)
        self.assertIsNone(su.string_column_index(lambda c, i: False, 10))


class SelfTest(unittest.TestCase):
    def test_module_selftest_passes(self):
        su.selftest()  # raises on failure


if __name__ == "__main__":
    unittest.main()
