#!/usr/bin/env python3
"""
benchmark.py -- Redstrike RECALL benchmark.

Precision is already strong (every reported finding is independently verified); recall -- "what did we
MISS?" -- is the unmeasured axis. This scores recall against a labelled target and flags regressions.

Two answer-key kinds:
  * http-json     -- a live app whose ground truth is enumerable (OWASP Juice Shop: 116 challenges, each
                     machine-checkable via GET /api/Challenges with a boolean `solved`). recall = solved/total.
  * findings-match-- target-agnostic: an `expected` vuln manifest matched against an engagement's REPORTED
                     findings (accepted/blocked, non-composite). No live solved-API needed, so ANY labelled
                     app can be scored from a run's output. Guards against Juice-Shop overfitting.

Positioning: the live recall RUN needs a live target + a real engagement, so it is an OPERATOR workflow (see
benchmark/RUNBOOK.md), NOT a push-CI job. What CI runs is `--selftest` (deterministic, no network) via
scripts/validate.py, so the harness + target specs + category maps can't rot.

  --score     Compute recall (overall + per native category + per difficulty) from a live --base-url, a
              captured --answer-key dump, or (findings-match) an --engagement dir. Optionally --out JSON.
  --baseline  Score, then record it as benchmark/baselines/<target>.json (the floor to beat).
  --check     Score, compare to the recorded baseline, and EXIT 2 on any recall regression > --tolerance.
  --map       Print the target's native-category -> Redstrike routing-map-category mapping (validated).
  --selftest  Validate every target spec + the scoring/regression logic. No network. (CI runs this.)

Stdlib only. Examples:
  python scripts/benchmark.py --selftest
  python scripts/benchmark.py --score --target juice-shop --base-url http://localhost:3000
  python scripts/benchmark.py --score --target juice-shop --answer-key challenges.json
  python scripts/benchmark.py --score --target generic-web --engagement engagements/<client>-<date>
  python scripts/benchmark.py --check --target juice-shop --answer-key challenges.json --tolerance 0.02
"""
import argparse
import datetime
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmark"
TARGETS = BENCH / "targets"
BASELINES = BENCH / "baselines"
RESULTS = BENCH / "results"
MAP_PATH = ROOT / "skills" / "_contract" / "routing-map.json"


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def load_target(name: str) -> dict:
    p = TARGETS / f"{name}.json"
    if not p.is_file():
        avail = ", ".join(sorted(t.stem for t in TARGETS.glob("*.json"))) or "(none)"
        sys.exit(f"[!] unknown target '{name}'. Available: {avail}")
    t = _read_json(p)
    if t is None:
        sys.exit(f"[!] target '{name}' invalid JSON")
    return t


def _dig(obj, path: str):
    for key in (path.split(".") if path else []):
        obj = obj[key]
    return obj


def fetch_answer_key(target: dict, base_url: str = None, answer_key_file: str = None) -> list:
    """Return [{id, category, solved, difficulty}] from the live endpoint or a captured dump.
    A dump is either the raw /api/Challenges JSON, {'data': [...]}, or a bare list of challenges."""
    ak = target["answer_key"]
    if answer_key_file:
        raw = _read_json(Path(answer_key_file))
        if raw is None:
            sys.exit(f"[!] answer-key dump unreadable: {answer_key_file}")
    else:
        if not base_url:
            sys.exit("[!] need --base-url (live) or --answer-key (captured dump)")
        import urllib.request
        url = base_url.rstrip("/") + ak["endpoint"]
        try:
            with urllib.request.urlopen(url, timeout=20) as r:  # noqa: S310 — operator-supplied target
                raw = json.loads(r.read().decode("utf-8", "replace"))
        except Exception as e:  # noqa: BLE001
            sys.exit(f"[!] could not fetch answer key from {url}: {e}")
    rows = raw if isinstance(raw, list) else _dig(raw, ak.get("data_path", "data"))
    out = []
    for r in rows:
        out.append({
            "id": r.get(ak["id_field"]),
            "category": r.get(ak["category_field"], "(uncategorized)"),
            "solved": bool(r.get(ak["solved_field"])),
            "difficulty": r.get(ak.get("difficulty_field", "difficulty")),
        })
    if not out:
        sys.exit("[!] answer key is empty -- is the target seeded and reachable?")
    return out


# --- engagement findings discovery (mirrors verify_completion/console: multi-layout + reportable) ----
def _findings_list(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return list(data.get("findings") or [])
    return []


def _discover_findings(eng: Path):
    """All findings across the layouts the pipeline produces, else None if the dir holds no findings file:
    the consolidated report, else a root findings.json, else the UNION of per-skill <eng>/*/findings.json."""
    cons = eng / "report" / "findings_consolidated.json"
    if cons.is_file():
        return _findings_list(_read_json(cons))
    root = eng / "findings.json"
    if root.is_file():
        return _findings_list(_read_json(root))
    per = sorted(eng.glob("*/findings.json"))
    if per:
        union = []
        for p in per:
            union.extend(_findings_list(_read_json(p)))
        return union
    return None


def _verdict(f: dict) -> str:
    r = f.get("review") or {}
    if r.get("verdict"):
        return r["verdict"]
    st = f.get("status")
    return "rejected" if st == "rejected" else "accepted" if st == "verified" else ""


def _reportable(f: dict) -> bool:
    composite = bool(f.get("composite") or f.get("_composite"))
    return (not composite) and _verdict(f) in ("accepted", "blocked")


def _load_findings(eng: Path) -> list:
    """REPORTED findings (accepted/blocked, non-composite) from an engagement, normalized for matching.
    Works with every findings layout a real run produces, so recall credits what actually got reported."""
    if not eng.is_dir():
        sys.exit(f"[!] engagement dir not found: {eng}")
    findings = _discover_findings(eng)
    if findings is None:
        sys.exit(f"[!] no findings.json under {eng} (root, per-skill, or report/findings_consolidated.json)")
    out = []
    for f in findings:
        if isinstance(f, dict) and _reportable(f):
            cat = f.get("category") or {}
            out.append({"owasp": str(cat.get("owasp", "")), "cwe": str(cat.get("cwe", "")),
                        "wstg": str(cat.get("wstg", "")), "title": str(f.get("title", ""))})
    return out


def _match_expected(m: dict, f: dict) -> bool:
    """A finding f satisfies an expected matcher m when EVERY declared key matches."""
    if m.get("owasp") and not f["owasp"].upper().startswith(m["owasp"].upper()):
        return False
    if m.get("cwe") and f["cwe"].upper() != m["cwe"].upper():
        return False
    if m.get("wstg") and m["wstg"].upper() not in f["wstg"].upper():
        return False
    if m.get("title_regex") and not re.search(m["title_regex"], f["title"], re.I):
        return False
    return bool(m)  # an empty matcher never matches (avoids a free pass)


def _expected_challenges(target: dict, findings: list) -> list:
    """Turn an expected-vuln manifest + the run's findings into score()-compatible pseudo-rows,
    so the scorer / baseline / check all work unchanged for findings-match targets."""
    rows = []
    for e in target.get("expected", []):
        found = any(_match_expected(e.get("match") or {}, f) for f in findings)
        rows.append({"id": e.get("name", e.get("id")), "category": e.get("group", "expected"),
                     "solved": found, "difficulty": e.get("severity", "-")})
    if not rows:
        sys.exit("[!] findings-match target has no 'expected' manifest")
    return rows


def _recall(solved: int, total: int) -> float:
    return round(solved / total, 4) if total else 0.0


def score(challenges: list, target: dict, want_unsolved: bool = True) -> dict:
    total = len(challenges)
    solved = sum(1 for c in challenges if c["solved"])
    by_cat, by_diff, unsolved = {}, {}, {}
    for c in challenges:
        cat = c["category"]
        d = by_cat.setdefault(cat, {"solved": 0, "total": 0})
        d["total"] += 1
        d["solved"] += 1 if c["solved"] else 0
        if not c["solved"]:
            unsolved.setdefault(cat, []).append(c["id"])
        diff = str(c.get("difficulty"))
        dd = by_diff.setdefault(diff, {"solved": 0, "total": 0})
        dd["total"] += 1
        dd["solved"] += 1 if c["solved"] else 0
    for d in list(by_cat.values()) + list(by_diff.values()):
        d["recall"] = _recall(d["solved"], d["total"])
    res = {
        "target": target["target"],
        "scored_at": _now(),
        "overall": {"solved": solved, "total": total, "recall": _recall(solved, total)},
        "by_category": dict(sorted(by_cat.items(), key=lambda kv: kv[0])),
        "by_difficulty": {k: by_diff[k] for k in sorted(by_diff)},
    }
    if want_unsolved:
        res["unsolved"] = {k: sorted(v) for k, v in sorted(unsolved.items())}
    return res


def to_baseline(res: dict, provenance: str) -> dict:
    return {
        "target": res["target"],
        "recorded_at": _now(),
        "provenance": provenance,
        "overall": res["overall"],
        "by_category": {k: {kk: v[kk] for kk in ("solved", "total", "recall")}
                        for k, v in res["by_category"].items()},
    }


def load_baseline(name: str) -> dict:
    p = BASELINES / f"{name}.json"
    if not p.is_file():
        sys.exit(f"[!] no baseline for '{name}' -- record one first: "
                 f"benchmark.py --baseline --target {name} --base-url <url>")
    return _read_json(p)


def check(res: dict, base: dict, tolerance: float) -> dict:
    regress, improve, missing = [], [], []
    bo, co = base["overall"]["recall"], res["overall"]["recall"]
    if co < bo - tolerance:
        regress.append(("overall", bo, co))
    elif co > bo + 1e-9:
        improve.append(("overall", bo, co))
    cur = res["by_category"]
    for cat, b in base.get("by_category", {}).items():
        if cat not in cur:
            missing.append(cat)
            continue
        cr = cur[cat]["recall"]
        if cr < b["recall"] - tolerance:
            regress.append((cat, b["recall"], cr))
        elif cr > b["recall"] + 1e-9:
            improve.append((cat, b["recall"], cr))
    new_cats = [c for c in cur if c not in base.get("by_category", {})]
    return {"ok": not regress and not missing, "regressions": regress,
            "improvements": improve, "missing_categories": missing, "new_categories": new_cats}


def _print_score(res: dict):
    o = res["overall"]
    print(f"# Recall -- {res['target']}  (scored {res['scored_at']})")
    print(f"overall: {o['solved']}/{o['total']} = {o['recall']:.1%}\n")
    print(f"{'category':<28} {'recall':>8}  solved/total")
    for cat, d in res["by_category"].items():
        print(f"{cat:<28} {d['recall']:>7.1%}  {d['solved']}/{d['total']}")
    if res.get("by_difficulty"):
        print("\nby difficulty:  " + " ".join(
            f"{k}*={v['solved']}/{v['total']}" for k, v in res["by_difficulty"].items()))


def _validate_map(target: dict):
    """Return (errors, known_ids) for the target's category_map against the routing map."""
    rmap = _read_json(MAP_PATH)
    if not isinstance(rmap, dict):
        return [f"cannot read routing map: {MAP_PATH}"], set()
    known = {c["id"] for c in rmap["categories"]}
    errors = []
    for jscat, ids in target.get("category_map", {}).items():
        for cid in ids:
            if cid not in known:
                errors.append(f"category_map['{jscat}'] -> '{cid}' is not a routing-map category id")
    return errors, known


def selftest() -> int:
    specs = sorted(TARGETS.glob("*.json"))
    assert specs, "no target specs under benchmark/targets/"
    for p in specs:
        t = _read_json(p)
        assert isinstance(t, dict), f"{p.name} is not a JSON object"
        for k in ("target", "answer_key"):
            assert k in t, f"{p.name} missing '{k}'"
        ak_type = (t.get("answer_key") or {}).get("type", "http-json")
        if ak_type == "findings-match":
            exp = t.get("expected")
            assert isinstance(exp, list) and exp, f"{p.name} findings-match target needs a non-empty 'expected'"
            for e in exp:
                assert e.get("match"), f"{p.name} expected item '{e.get('id')}' has no 'match'"
        else:
            assert "category_map" in t, f"{p.name} (http-json) missing 'category_map'"
            for k in ("endpoint", "id_field", "category_field", "solved_field"):
                assert k in t["answer_key"], f"{p.name} answer_key missing '{k}'"
            errs, _ = _validate_map(t)
            assert not errs, f"{p.name}: " + "; ".join(errs)
    # scoring logic on a tiny synthetic key
    fake = [{"id": "a", "category": "X", "solved": True, "difficulty": 1},
            {"id": "b", "category": "X", "solved": False, "difficulty": 2},
            {"id": "c", "category": "Y", "solved": True, "difficulty": 1}]
    res = score(fake, {"target": "t"})
    assert res["overall"] == {"solved": 2, "total": 3, "recall": 0.6667}, res["overall"]
    assert res["by_category"]["X"]["recall"] == 0.5
    base = to_baseline(res, "selftest")
    # a drop in Y is a regression; an overall rise is an improvement
    worse = score([{"id": "c", "category": "Y", "solved": False, "difficulty": 1},
                   {"id": "a", "category": "X", "solved": True, "difficulty": 1},
                   {"id": "b", "category": "X", "solved": True, "difficulty": 2}], {"target": "t"})
    chk = check(worse, base, 0.0)
    assert any(r[0] == "Y" for r in chk["regressions"]), "Y regression not caught"
    assert not chk["ok"]
    # findings-match path (target-agnostic): expected manifest matched against a run's findings
    tgt = {"target": "t", "expected": [
        {"id": "sqli", "name": "SQLi", "group": "injection", "match": {"cwe": "CWE-89"}},
        {"id": "xss", "name": "XSS", "group": "injection", "match": {"cwe": "CWE-79"}},
        {"id": "ssrf", "name": "SSRF", "group": "ssrf", "match": {"cwe": "CWE-918"}}]}
    fnd = [{"owasp": "A03:2021-Injection", "cwe": "CWE-89", "wstg": "", "title": "SQLi in login"}]
    fm = score(_expected_challenges(tgt, fnd), tgt)
    assert fm["overall"] == {"solved": 1, "total": 3, "recall": 0.3333}, fm["overall"]
    assert not _match_expected({}, fnd[0]), "empty matcher must not match"
    print(f"benchmark.py selftest: OK ({len(specs)} target spec(s), http-json + findings-match scoring verified)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Redstrike recall benchmark.")
    ap.add_argument("--score", action="store_true")
    ap.add_argument("--baseline", action="store_true", help="record the current score as the baseline")
    ap.add_argument("--check", action="store_true", help="compare to baseline; exit 2 on regression")
    ap.add_argument("--map", action="store_true", dest="show_map")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--target", help="target name under benchmark/targets/")
    ap.add_argument("--base-url", help="live base URL of the running target")
    ap.add_argument("--answer-key", help="captured answer-key JSON dump (instead of --base-url)")
    ap.add_argument("--engagement", help="engagement dir (findings-match targets score its findings)")
    ap.add_argument("--tolerance", type=float, default=0.0, help="allowed recall drop before it's a regression")
    ap.add_argument("--out", help="write the full result JSON here")
    ap.add_argument("--provenance", default="", help="note stored with a --baseline (how it was produced)")
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.target:
        ap.error("need --target (or --selftest)")
    target = load_target(args.target)

    if args.show_map:
        errs, _ = _validate_map(target)
        print(f"# {target.get('name', target['target'])} category map -> Redstrike routing-map categories")
        for jscat, ids in target.get("category_map", {}).items():
            print(f"  {jscat:<28} -> {', '.join(ids)}")
        if errs:
            print("\nERRORS:")
            for e in errs:
                print(f"  - {e}")
            return 2
        print("\nall mapped ids exist in routing-map.json.")
        return 0

    ak_type = (target.get("answer_key") or {}).get("type", "http-json")
    if ak_type == "findings-match":
        if not args.engagement:
            ap.error("a findings-match target needs --engagement <dir> (the run's output)")
        challenges = _expected_challenges(target, _load_findings(Path(args.engagement)))
    else:
        challenges = fetch_answer_key(target, args.base_url, args.answer_key)
    res = score(challenges, target)
    if args.out:
        op = Path(args.out)
        op.parent.mkdir(parents=True, exist_ok=True)
        op.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")

    if args.baseline:
        BASELINES.mkdir(parents=True, exist_ok=True)
        prov = args.provenance or f"scored {res['scored_at']} from {args.answer_key or args.base_url or args.engagement}"
        bl = to_baseline(res, prov)
        (BASELINES / f"{args.target}.json").write_text(json.dumps(bl, indent=2) + "\n", encoding="utf-8")
        _print_score(res)
        print(f"\nwrote baseline -> benchmark/baselines/{args.target}.json")
        return 0

    if args.check:
        base = load_baseline(args.target)
        chk = check(res, base, args.tolerance)
        if args.as_json:
            print(json.dumps({"result": res["overall"], "check": chk}, indent=2))
        else:
            _print_score(res)
            print(f"\n# Regression check vs baseline ({base['recorded_at']}, tol {args.tolerance:.0%})")
            for cat, b, c in chk["regressions"]:
                print(f"  REGRESS  {cat:<26} {b:.1%} -> {c:.1%}")
            for cat in chk["missing_categories"]:
                print(f"  MISSING  {cat:<26} (in baseline, absent now)")
            for cat, b, c in chk["improvements"]:
                print(f"  up       {cat:<26} {b:.1%} -> {c:.1%}")
            if chk["new_categories"]:
                print(f"  new categories (not in baseline): {', '.join(chk['new_categories'])}")
            print(f"\n{'PASS' if chk['ok'] else 'FAIL'}: "
                  + ("no recall regression." if chk["ok"] else "recall regressed (see above)."))
        return 0 if chk["ok"] else 2

    if args.score:
        if args.as_json:
            print(json.dumps(res, indent=2))
        else:
            _print_score(res)
        return 0

    ap.error("choose one of --score / --baseline / --check / --map / --selftest")


if __name__ == "__main__":
    sys.exit(main())
