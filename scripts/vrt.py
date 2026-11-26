#!/usr/bin/env python3
"""
vrt.py -- deterministic Vulnerability Rating Taxonomy (VRT) resolver (Redstrike).

Turns a finding's CWE / executor-class into the REAL Bugcrowd VRT path + the taxonomy's
own baseline priority, so a bug-bounty submission's VRT is RESOLVED from the pinned
taxonomy instead of improvised. This exists because a FABRICATED VRT category once shipped
in a submission (an operator caught it); the governance core makes that impossible to do
silently. A sibling submission generator imports this module — the public interface
(`load_vrt`, `path_exists`, `resolve_finding_vrt`, `elevation_errors`) is a contract, do
not rename it.

Two offline data files, both pinned + vendored (no runtime egress):
  * skills/bug-bounty/refs/vrt/vulnerability-rating-taxonomy.json  -- the source of truth
    for valid VRT paths + baseline priorities (THIS module reads priorities only from here).
  * skills/bug-bounty/refs/vrt/vrt_crosswalk.json                  -- CWE/class -> VRT path.

Priority grammar: an integer 1 (most severe) .. 5 (least), rendered as "P1".."P5"; the
string/None value "varies" means the taxonomy assigns the priority per context (the node
has no numeric baseline). Stdlib only.

Usage:
  python scripts/vrt.py --resolve --cwe CWE-79          # -> path/id/priority/baseline
  python scripts/vrt.py --resolve --category xss-reflected
  python scripts/vrt.py --validate-path "server_side_injection > sql_injection"
  python scripts/vrt.py --selftest                      # CI self-check
"""
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
_VRT_DIR = os.path.join(_REPO, "skills", "bug-bounty", "refs", "vrt")
TAXONOMY_PATH = os.path.join(_VRT_DIR, "vulnerability-rating-taxonomy.json")
CROSSWALK_PATH = os.path.join(_VRT_DIR, "vrt_crosswalk.json")

# module caches (populated on first use)
_TAXONOMY = None
_FLAT = None
_CROSSWALK = None


class VrtError(ValueError):
    """Raised when the taxonomy/crosswalk cannot be loaded or a path cannot be parsed."""


# --------------------------------------------------------------------------- #
# loading + flattening
# --------------------------------------------------------------------------- #
def load_vrt() -> dict:
    """Load + cache the pinned VRT taxonomy (the parsed JSON dict)."""
    global _TAXONOMY
    if _TAXONOMY is None:
        try:
            with open(TAXONOMY_PATH, encoding="utf-8") as fh:
                _TAXONOMY = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            raise VrtError(f"cannot load pinned taxonomy {TAXONOMY_PATH}: {e}")
    return _TAXONOMY


def _load_crosswalk() -> dict:
    """Load + cache the CWE/class -> VRT crosswalk."""
    global _CROSSWALK
    if _CROSSWALK is None:
        try:
            with open(CROSSWALK_PATH, encoding="utf-8") as fh:
                _CROSSWALK = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            raise VrtError(f"cannot load crosswalk {CROSSWALK_PATH}: {e}")
    return _CROSSWALK


def _norm_path(path_or_id: str):
    """'A > B > C' -> ('a','b','c'); segment-wise stripped + lowercased, empty segments dropped."""
    return tuple(seg.strip().lower() for seg in str(path_or_id).split(">") if seg.strip())


def _flatten():
    """Flatten the taxonomy `content` tree (cached) to:
         id_paths   { (id,...): priority|None }
         name_paths { (name,...): priority|None }   (display-name path, lowercased)
         leaf_ids   { 'leaf_id': True }
       A node's priority is an int 1-5 or None ('varies'). EVERY node is recorded (the VRT
       assigns priorities at category/subcategory level too, not only at the variant leaf)."""
    global _FLAT
    if _FLAT is not None:
        return _FLAT
    tax = load_vrt()
    id_paths, name_paths, leaf_ids = {}, {}, {}

    def walk(node, idtrail, nametrail):
        nid = node.get("id")
        if not isinstance(nid, str) or not nid.strip():
            return
        it = idtrail + (nid.strip().lower(),)
        nm = node.get("name", nid)
        nt = nametrail + (str(nm).strip().lower(),)
        prio = node.get("priority", None)
        id_paths[it] = prio
        name_paths[nt] = prio
        leaf_ids[it[-1]] = True
        for c in node.get("children") or []:
            if isinstance(c, dict):
                walk(c, it, nt)

    for cat in (tax or {}).get("content", []):
        if isinstance(cat, dict):
            walk(cat, (), ())
    _FLAT = {"id_paths": id_paths, "name_paths": name_paths, "leaf_ids": leaf_ids}
    return _FLAT


# --------------------------------------------------------------------------- #
# priority helpers
# --------------------------------------------------------------------------- #
def _prio_int(value):
    """'P3'/'3'/3 -> 3 ; None/''/'varies' -> None. Raises VrtError on anything else."""
    if value is None:
        return None
    if isinstance(value, bool):
        raise VrtError(f"{value!r} is not a P1-P5 priority")
    if isinstance(value, int):
        if 1 <= value <= 5:
            return value
        raise VrtError(f"{value!r} is out of the P1-P5 range")
    s = str(value).strip()
    if not s or s.lower() == "varies":
        return None
    if s and s[0] in "Pp":
        s = s[1:]
    if s.isdigit() and 1 <= int(s) <= 5:
        return int(s)
    raise VrtError(f"{value!r} is not a P1-P5 priority (or 'varies')")


def _prio_str(n):
    """3 -> 'P3' ; None -> None."""
    return f"P{n}" if isinstance(n, int) else None


# --------------------------------------------------------------------------- #
# resolution
# --------------------------------------------------------------------------- #
def _resolve_key(path_or_id: str):
    """Resolve a '>'-joined display-path OR id-path (or a bare leaf id) to the matching
       flattened key. Returns (space, key) where space is 'id'/'name', or (None, None)."""
    flat = _flatten()
    norm = _norm_path(path_or_id)
    if not norm:
        return None, None
    if norm in flat["id_paths"]:
        return "id", norm
    if norm in flat["name_paths"]:
        return "name", norm
    return None, None


def path_exists(path_or_id: str) -> bool:
    """True iff the display-path (names joined by '>') OR the id-path OR a bare leaf id
       resolves to a real node in the pinned taxonomy. A fabricated path -> False."""
    space, _ = _resolve_key(path_or_id)
    if space is not None:
        return True
    norm = _norm_path(path_or_id)
    # a single bare token may be a leaf variant/subcategory id
    if len(norm) == 1:
        return norm[0] in _flatten()["leaf_ids"]
    return False


def _baseline_and_ceiling(path_or_id: str):
    """For a resolvable path, return (baseline:int|None, ceiling:int|None):
         baseline = the node's own priority (None = 'varies').
         ceiling  = the MOST SEVERE priority (lowest P-number) among the node's STRICT
                    descendants, or None if the node is a leaf / no descendant carries one.
       The ceiling is 'what the path's real variants allow': a parent category can't be
       rated stronger than the most severe variant the taxonomy itself places under it.
       Returns (None, None) with resolved=False when the path does not resolve."""
    space, key = _resolve_key(path_or_id)
    if space is None:
        return None, None, False
    flat = _flatten()
    table = flat["id_paths"] if space == "id" else flat["name_paths"]
    baseline = table.get(key)
    n = len(key)
    desc = [p for k, p in table.items()
            if len(k) > n and k[:n] == key and isinstance(p, int)]
    ceiling = min(desc) if desc else None
    return baseline, ceiling, True


def resolve_finding_vrt(cwe=None, category=None):
    """Crosswalk lookup -> {"path","id","priority","baseline"} or None.

    `category` is a redstrike executor class slug (e.g. 'xss-reflected'); `cwe` is a
    'CWE-79'-style id. The class slug is preferred when both are given and mapped (it is
    more specific than the CWE). `priority` DEFAULTS to the resolved path's taxonomy
    baseline (rendered 'P1'..'P5', or None for a 'varies' node); `baseline` is the same.
    A class/CWE with no crosswalk entry -> None (a legitimate unmapped state)."""
    xw = _load_crosswalk()
    entry = None
    if category:
        entry = (xw.get("class") or {}).get(str(category).strip().lower())
    if entry is None and cwe:
        entry = (xw.get("cwe") or {}).get(_norm_cwe(cwe))
    if entry is None:
        return None
    for cand in _candidates(entry):
        path = cand.get("path")
        if path and path_exists(path):
            baseline, _ceiling, _ok = _baseline_and_ceiling(path)
            return {
                "path": path,
                "id": cand.get("id") or (_norm_path(path)[-1] if _norm_path(path) else None),
                "priority": _prio_str(baseline),   # defaults to the taxonomy baseline
                "baseline": _prio_str(baseline),
            }
    return None


def _candidates(entry):
    """Normalize a crosswalk entry to an ordered list of {path,id} candidate dicts."""
    if isinstance(entry, dict) and isinstance(entry.get("candidates"), list):
        return [c for c in entry["candidates"] if isinstance(c, dict)]
    if isinstance(entry, dict) and entry.get("path"):
        return [entry]
    return []


def _norm_cwe(cwe) -> str:
    """'79'/'cwe-79'/'CWE-79' -> 'CWE-79'."""
    s = str(cwe).strip().upper()
    if s.startswith("CWE-"):
        return s
    if s.startswith("CWE"):
        s = s[3:].lstrip("-")
    return f"CWE-{s}" if s else s


# --------------------------------------------------------------------------- #
# anti-inflation: priority vs baseline / variant ceiling
# --------------------------------------------------------------------------- #
def elevation_errors(path, priority, basis=None, rationale=None):
    """Return [] if the priority is allowed for the path, else a list of error strings.

    Rules (lower P-number = MORE severe):
      * the path must resolve in the pinned taxonomy (a fabricated path is an error);
      * a priority STRONGER than the path's taxonomy baseline requires
        basis == 'argued-elevation' AND a non-empty rationale (anti-INFLATION);
      * a basis of 'argued-elevation'/'argued-reduction' always requires a rationale;
      * the priority may NOT exceed what the path's real variants allow — i.e. it may not
        be more severe than the MOST SEVERE descendant variant the taxonomy places under
        the path (this ceiling cannot be argued past).
    A priority of None ('varies') makes no claim and is never an error."""
    errs = []
    try:
        claimed = _prio_int(priority)
    except VrtError as e:
        return [f"vrt.priority {e}"]
    if claimed is None:
        return errs  # no priority asserted -> nothing to validate
    baseline, ceiling, resolved = _baseline_and_ceiling(path)
    if not resolved:
        return [f"vrt path {path!r} does not resolve in the pinned taxonomy (fabricated VRT category)"]
    basis = (basis or "baseline").strip()
    rationale = (rationale or "").strip()
    if basis not in ("baseline", "argued-elevation", "argued-reduction"):
        errs.append(f"vrt.priority_basis {basis!r} must be baseline/argued-elevation/argued-reduction")
    # anti-inflation vs the node's own baseline
    if isinstance(baseline, int) and claimed < baseline:
        if basis != "argued-elevation":
            errs.append(f"vrt.priority P{claimed} is STRONGER than the taxonomy baseline P{baseline} "
                        f"but priority_basis is {basis!r} — inflation; require 'argued-elevation' + a "
                        f"priority_rationale")
        elif not rationale:
            errs.append(f"vrt.priority P{claimed} elevated above baseline P{baseline} (argued-elevation) "
                        f"but priority_rationale is empty")
    elif basis in ("argued-elevation", "argued-reduction") and not rationale:
        errs.append(f"vrt.priority_basis {basis!r} requires a non-empty priority_rationale")
    # the variant ceiling: cannot be more severe than the taxonomy's own strongest variant here
    if isinstance(ceiling, int) and claimed < ceiling:
        errs.append(f"vrt.priority P{claimed} exceeds what this path's real variants allow — the most "
                    f"severe priority the taxonomy assigns under {path!r} is P{ceiling} (not an allowed "
                    f"elevation even with a rationale; pick the matching variant)")
    return errs


# --------------------------------------------------------------------------- #
# self-test (imported by scripts/validate.py; asserts, raising on failure)
# --------------------------------------------------------------------------- #
def selftest() -> None:
    """Deterministic self-check against the pinned taxonomy + crosswalk. Raises
    AssertionError on the first failure (quiet; the CLI wrapper prints a report)."""
    # --- path_exists ---
    assert path_exists("server_side_injection > sql_injection"), "real id-path must resolve"
    assert path_exists("Server-Side Injection > SQL Injection"), "real display-name path must resolve"
    assert path_exists("sql_injection"), "a bare leaf id must resolve"
    assert path_exists("server_side_injection > content_spoofing > text_injection"), "anchor path"
    assert not path_exists("Broken Access Control / Server-Side Improper Authorization"), \
        "a fabricated path must NOT resolve (the incident category)"
    assert not path_exists("totally_made_up_node"), "a fabricated leaf id must NOT resolve"

    # --- resolve_finding_vrt ---
    r = resolve_finding_vrt(cwe="CWE-79")
    assert r and r["path"] == "cross_site_scripting_xss > reflected > non_self" and r["priority"] == "P3", r
    assert resolve_finding_vrt(cwe="79")["id"] == "non_self", "CWE normalization (bare number)"
    assert resolve_finding_vrt(category="sqli-inband")["priority"] == "P1", "SQLi -> P1"
    assert resolve_finding_vrt(category="idor")["priority"] == "P3", "IDOR default -> P3"
    # class slug preferred over CWE when both resolve
    rc = resolve_finding_vrt(cwe="CWE-89", category="xss-reflected")
    assert rc["path"].startswith("cross_site_scripting_xss"), "class slug wins over cwe"
    assert resolve_finding_vrt(cwe="CWE-0000") is None, "an unmapped CWE -> None"
    assert resolve_finding_vrt(category="not-a-class") is None, "an unmapped class -> None"
    # a 'varies' node resolves with a None priority
    rv = resolve_finding_vrt(category="cors")
    assert rv and rv["priority"] is None and rv["baseline"] is None, rv

    # --- elevation_errors ---
    ssi_ti = "server_side_injection > content_spoofing > text_injection"       # baseline P5 leaf
    ssi_if = "server_side_injection > content_spoofing > iframe_injection"     # baseline P3 leaf
    assert elevation_errors(ssi_ti, "P5", "baseline", None) == [], "baseline passes"
    # inflation: P3 on a P5-baseline leaf with no argued basis -> error
    assert elevation_errors(ssi_ti, "P3", "baseline", None), "P3-on-P5 without basis must fail"
    assert elevation_errors(ssi_ti, "P3", "argued-elevation", None), "argued-elevation needs a rationale"
    assert elevation_errors(ssi_ti, "P3", "argued-elevation",
                            "demonstrated cross-user nickname spoofing") == [], "argued elevation ok"
    # argued reduction below baseline (weaker) needs a rationale
    assert elevation_errors(ssi_if, "P5", "argued-reduction", "no sensitive action framed") == [], \
        "argued reduction with rationale ok"
    assert elevation_errors(ssi_if, "P5", "argued-reduction", None), "argued reduction needs a rationale"
    # variant ceiling: content_spoofing's strongest variant is P3 (iframe); P1 is not allowed even argued
    cs = "server_side_injection > content_spoofing"
    assert elevation_errors(cs, "P1", "argued-elevation", "trying to over-rate"), \
        "claiming P1 on a path whose strongest variant is P3 must fail"
    assert elevation_errors(cs, "P3", "baseline", None) == [], "P3 matches the strongest variant"
    # fabricated path
    assert elevation_errors("not > a > real > path", "P3", "baseline", None), "fabricated path must fail"
    # 'varies'/None priority makes no claim
    assert elevation_errors(ssi_ti, None, "baseline", None) == [], "None priority is not a claim"
    # bad priority token
    assert elevation_errors(ssi_ti, "P9", "baseline", None), "a bad priority token must fail"


def _selftest_cli() -> int:
    """CLI wrapper around selftest(): prints PASS/FAIL and returns an exit code."""
    try:
        selftest()
    except AssertionError as e:
        print(f"FAIL: vrt selftest: {e}")
        return 1
    except VrtError as e:
        print(f"FAIL: vrt selftest could not load data: {e}")
        return 1
    print("PASS: vrt selftest (path_exists + resolve_finding_vrt + elevation_errors)")
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.strip())
        return 0
    if argv[0] == "--selftest":
        return _selftest_cli()
    if argv[0] == "--validate-path":
        if len(argv) < 2:
            print("error: --validate-path needs a path", file=sys.stderr)
            return 2
        p = argv[1]
        if path_exists(p):
            baseline, ceiling, _ = _baseline_and_ceiling(p)
            print(f"OK: {p!r} resolves (baseline {_prio_str(baseline) or 'varies'}"
                  + (f", strongest variant {_prio_str(ceiling)}" if ceiling else "") + ")")
            return 0
        print(f"FAIL: {p!r} does NOT resolve in the pinned taxonomy (fabricated VRT category)",
              file=sys.stderr)
        return 1
    if argv[0] == "--resolve":
        cwe = category = None
        i = 1
        while i < len(argv):
            if argv[i] == "--cwe" and i + 1 < len(argv):
                cwe = argv[i + 1]
                i += 2
            elif argv[i] == "--category" and i + 1 < len(argv):
                category = argv[i + 1]
                i += 2
            else:
                print(f"error: unexpected argument {argv[i]!r}", file=sys.stderr)
                return 2
        if not (cwe or category):
            print("error: --resolve needs --cwe and/or --category", file=sys.stderr)
            return 2
        res = resolve_finding_vrt(cwe=cwe, category=category)
        if res is None:
            print(json.dumps({"resolved": None,
                              "note": "no crosswalk entry (unmapped is a legitimate state)"}))
            return 1
        print(json.dumps(res, indent=2))
        return 0
    print(f"error: unknown argument {argv[0]!r} (try --resolve / --validate-path / --selftest)",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
