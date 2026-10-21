#!/usr/bin/env python3
"""
benchmark.py -- Redstrike RECALL benchmark (Phase 2).

Measure recall against a known answer key and gate CI on regressions. Precision is already strong
(every reported finding is independently verified); recall -- "what did we miss?" -- was unmeasured.
This scores it against a labelled target (OWASP Juice Shop first: 116 challenges, each machine-checkable
via GET /api/Challenges) and fails when recall drops.

  --score     Fetch the answer key (live --base-url, or a captured --answer-key dump) and print recall,
              overall + per native category + per difficulty. Optionally --out a result JSON.
  --baseline  Score, then record the result as benchmark/baselines/<target>.json (the floor to beat).
  --check     Score, compare to the recorded baseline, and EXIT NON-ZERO on any recall regression
              beyond --tolerance. This is the CI gate.
  --map       Print the target's Juice-Shop-category -> Redstrike-category mapping, validated against
              skills/_contract/routing-map.json.
  --selftest  Validate every target spec (parses, category_map ids exist in the routing map). No network.

Stdlib only. Examples:
  python scripts/benchmark.py --score    --target juice-shop --base-url http://localhost:3000
  python scripts/benchmark.py --baseline --target juice-shop --base-url http://localhost:3000
  python scripts/benchmark.py --check    --target juice-shop --base-url http://localhost:3000
  python scripts/benchmark.py --score    --target juice-shop --answer-key challenges.json
  python scripts/benchmark.py --selftest
"""
import argparse
import datetime
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmark"
TARGETS = BENCH / "targets"
BASELINES = BENCH / "baselines"
RESULTS = BENCH / "results"
MAP_PATH = ROOT / "skills" / "_contract" / "routing-map.json"


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_target(name: str) -> dict:
    p = TARGETS / f"{name}.json"
    if not p.is_file():
        avail = ", ".join(sorted(t.stem for t in TARGETS.glob("*.json"))) or "(none)"
        sys.exit(f"[!] unknown target '{name}'. Available: {avail}")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        sys.exit(f"[!] target '{name}' invalid JSON: {e}")


def _dig(obj, path: str):
    for key in (path.split(".") if path else []):
        obj = obj[key]
    return obj


def fetch_answer_key(target: dict, base_url: str = None, answer_key_file: str = None) -> list:
    """Return [{id, category, solved, difficulty}] from the live endpoint or a captured dump.
    A dump is either the raw /api/Challenges JSON, or {'data': [...]} , or a bare list of challenges."""
    ak = target["answer_key"]
    if answer_key_file:
        raw = json.loads(Path(answer_key_file).read_text(encoding="utf-8"))
    else:
        if not base_url:
            sys.exit("[!] need --base-url (live) or --answer-key (captured dump)")
        url = base_url.rstrip("/") + ak["endpoint"]
        try:
            with urllib.request.urlopen(url, timeout=20) as r:
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
    return json.loads(p.read_text(encoding="utf-8"))


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
    print("\nby difficulty:  " + " ".join(
        f"{k}*={v['solved']}/{v['total']}" for k, v in res["by_difficulty"].items()))


def _validate_map(target: dict):
    """Return (errors, known_ids) for the target's category_map against the routing map."""
    errors = []
    try:
        rmap = json.loads(MAP_PATH.read_text(encoding="utf-8"))
        known = {c["id"] for c in rmap["categories"]}
    except Exception as e:  # noqa: BLE001
        return [f"cannot read routing map: {e}"], set()
    for jscat, ids in target.get("category_map", {}).items():
        for cid in ids:
            if cid not in known:
                errors.append(f"category_map['{jscat}'] -> '{cid}' is not a routing-map category id")
    return errors, known


def selftest() -> int:
    specs = sorted(TARGETS.glob("*.json"))
    assert specs, "no target specs under benchmark/targets/"
    for p in specs:
        t = json.loads(p.read_text(encoding="utf-8"))
        for k in ("target", "answer_key", "category_map"):
            assert k in t, f"{p.name} missing '{k}'"
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
    print(f"benchmark.py selftest: OK ({len(specs)} target spec(s), scoring + regression logic verified)")
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
        print(f"# {target['name']} category map -> Redstrike routing-map categories")
        for jscat, ids in target.get("category_map", {}).items():
            print(f"  {jscat:<28} -> {', '.join(ids)}")
        if errs:
            print("\nERRORS:")
            for e in errs:
                print(f"  - {e}")
            return 2
        print("\nall mapped ids exist in routing-map.json.")
        return 0

    challenges = fetch_answer_key(target, args.base_url, args.answer_key)
    res = score(challenges, target)
    if args.out:
        op = Path(args.out)
        op.parent.mkdir(parents=True, exist_ok=True)
        op.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")

    if args.baseline:
        BASELINES.mkdir(parents=True, exist_ok=True)
        prov = args.provenance or f"scored {res['scored_at']} from {args.answer_key or args.base_url}"
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
