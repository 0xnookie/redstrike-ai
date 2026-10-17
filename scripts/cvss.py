#!/usr/bin/env python3
"""
cvss.py -- deterministic CVSS base-score calculator (Redstrike).

Turns a CVSS vector string into a numeric base score + severity rating, so
executors and the `reporting` skill compute scores instead of asserting them by
hand (the #1 source of score/vector drift that reviewers kept flagging). The
`verify_completion.py --engagement` gate imports this to warn when a finding's
declared `severity` disagrees with its `cvss_vector`.

Supports CVSS v3.0 / v3.1 BASE metrics (what Redstrike findings use). v4.0 vectors
are detected and reported as unsupported rather than mis-scored. Stdlib only.

Usage:
  python scripts/cvss.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"   # -> 9.8 Critical
  python scripts/cvss.py --rating "CVSS:3.1/..."                           # -> Critical
  python scripts/cvss.py --selftest                                       # CI self-check
"""
import sys

# --- CVSS v3.1 base metric weights (first.org specification) ---
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
# Privileges Required depends on Scope (changed grants a higher weight to L/H).
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}

_BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


class CvssError(ValueError):
    """Raised when a vector cannot be parsed or scored."""


def parse_vector(vector: str) -> dict:
    """Parse a CVSS vector into {metric: value}. Keeps non-base metrics too."""
    if not vector or not isinstance(vector, str):
        raise CvssError("empty vector")
    parts = [p for p in vector.strip().split("/") if p]
    version = "3.1"
    metrics = {}
    for p in parts:
        if ":" not in p:
            raise CvssError(f"malformed component {p!r}")
        k, v = p.split(":", 1)
        if k == "CVSS":
            version = v
            continue
        metrics[k] = v
    metrics["_version"] = version
    return metrics


def _roundup(x: float) -> float:
    """Official CVSS 3.1 Roundup: smallest 1-decimal value >= x (avoids FP drift)."""
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (i // 10000 + 1) / 10.0


def rating_for(score: float) -> str:
    """CVSS 3.x qualitative severity rating for a base score."""
    if score <= 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def base_score(metrics: dict) -> float:
    """Compute the CVSS v3.0/3.1 base score from parsed base metrics."""
    version = metrics.get("_version", "3.1")
    if version.startswith("4"):
        raise CvssError("CVSS v4.0 scoring is not supported (base-metric parse only)")
    missing = [m for m in _BASE_METRICS if m not in metrics]
    if missing:
        raise CvssError(f"missing base metric(s): {','.join(missing)}")

    scope_changed = metrics["S"] == "C"
    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        ui = _UI[metrics["UI"]]
        pr = (_PR_C if scope_changed else _PR_U)[metrics["PR"]]
        c, i, a = _CIA[metrics["C"]], _CIA[metrics["I"]], _CIA[metrics["A"]]
    except KeyError as e:
        raise CvssError(f"invalid metric value {e}")

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    raw = (1.08 * (impact + exploitability)) if scope_changed else (impact + exploitability)
    return _roundup(min(raw, 10.0))


def score_vector(vector: str):
    """vector -> (score: float, rating: str, version: str)."""
    metrics = parse_vector(vector)
    score = base_score(metrics)
    return score, rating_for(score), metrics.get("_version", "3.1")


# Canonical first.org reference values — used by --selftest and CI (validate.py).
_SELFTEST = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "Critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1, "Critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "Medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "High"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "Medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 4.3, "Medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "None"),
]


def _selftest() -> int:
    bad = 0
    for vec, want_score, want_rating in _SELFTEST:
        try:
            score, rating, _ = score_vector(vec)
        except CvssError as e:
            print(f"FAIL {vec}: {e}")
            bad += 1
            continue
        ok = abs(score - want_score) < 1e-9 and rating == want_rating
        print(f"{'ok  ' if ok else 'FAIL'} {vec} -> {score} {rating}"
              + ("" if ok else f"  (expected {want_score} {want_rating})"))
        bad += not ok
    print(f"\n{'PASS' if not bad else 'FAIL'}: {len(_SELFTEST) - bad}/{len(_SELFTEST)} cases")
    return 1 if bad else 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.strip())
        return 0
    if argv[0] == "--selftest":
        return _selftest()
    rating_only = False
    if argv[0] == "--rating":
        rating_only = True
        argv = argv[1:]
    if not argv:
        print("error: no vector given", file=sys.stderr)
        return 2
    try:
        score, rating, version = score_vector(argv[0])
    except CvssError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(rating if rating_only else f"{score} {rating} (CVSS v{version} base)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
