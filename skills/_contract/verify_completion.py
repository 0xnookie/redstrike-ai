#!/usr/bin/env python3
"""
verify_completion.py -- Redstrike MECHANICAL completion gate (the review.md altitude).

Reads the fenced ```json manifest from a skill's review.md, checks each declared
artifact in an engagement output directory (exists, non-zero, valid format,
plausible size), prints a per-item PASS/FAIL ledger, and exits non-zero if any
REQUIRED artifact fails -- so an orchestrator can treat a nonzero exit as
"re-run the unchecked steps".

This gate is deterministic and makes NO judgment about whether findings are real.
That is the job of verify.md (the semantic gate). See _contract/README.md.

Stdlib only. Usage:
  python verify_completion.py --skill skills/js-analysis --out <engagement_out_dir>
  python verify_completion.py --review skills/js-analysis/review.md --out <dir> --json
"""
import argparse
import glob as globmod
import json
import os
import re
import sys
from pathlib import Path

FENCE_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)


def load_manifest(review_path: Path) -> dict:
    if not review_path.is_file():
        sys.exit(f"[!] no review.md at {review_path}")
    text = review_path.read_text(encoding="utf-8", errors="replace")
    for m in FENCE_RE.finditer(text):
        try:
            obj = json.loads(m.group(1))
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "artifacts" in obj:
            return obj
    sys.exit(f"[!] no JSON manifest (object with 'artifacts') found in {review_path}")


def check_artifact(a: dict, out: Path):
    typ = a.get("type", "text")
    rel = a.get("path", "")
    p = out / rel
    min_bytes = a.get("min_bytes", 1)

    if typ == "glob":
        matches = [x for x in globmod.glob(str(out / rel), recursive=True)
                   if os.path.isfile(x) and os.path.getsize(x) > 0]
        need = a.get("min_matches", 1)
        if len(matches) >= need:
            return True, f"{len(matches)} non-empty match(es)"
        return False, f"glob '{rel}' matched {len(matches)} non-empty file(s), need {need}"

    if typ == "dir":
        if not p.is_dir():
            return False, f"missing dir {rel}"
        children = list(p.iterdir())
        need = a.get("min_children", 1)
        if len(children) < need:
            return False, f"dir {rel} has {len(children)} child(ren), need {need}"
        return True, f"{len(children)} child(ren)"

    if not p.is_file():
        return False, f"missing file {rel}"
    size = p.stat().st_size
    if size < min_bytes:
        return False, f"{rel} is {size} B, need >= {min_bytes} B"

    if typ in ("json", "jsonl"):
        raw = p.read_text(encoding="utf-8", errors="replace")
        if typ == "json":
            try:
                data = json.loads(raw)
            except json.JSONDecodeError as e:
                return False, f"{rel} invalid JSON: {e}"
            if isinstance(data, list) and not data and not a.get("allow_empty_array", False):
                return False, f"{rel} is an empty array"
            if isinstance(data, dict) and not data and not a.get("allow_empty_object", False):
                return False, f"{rel} is an empty object"
        else:  # jsonl
            lines = [ln for ln in raw.splitlines() if ln.strip()]
            need = a.get("min_items", 1)
            if len(lines) < need and not a.get("allow_empty", False):
                return False, f"{rel} has {len(lines)} record(s), need >= {need}"
            for i, ln in enumerate(lines[:50], 1):
                try:
                    json.loads(ln)
                except json.JSONDecodeError as e:
                    return False, f"{rel} line {i} invalid JSON: {e}"

    must = a.get("must_contain")
    if must and must not in p.read_text(encoding="utf-8", errors="replace"):
        return False, f"{rel} missing expected token {must!r}"

    return True, f"{size} B"


def main() -> None:
    ap = argparse.ArgumentParser(description="Redstrike mechanical completion gate.")
    ap.add_argument("--skill", help="skill dir containing review.md")
    ap.add_argument("--review", help="path to review.md (overrides --skill)")
    ap.add_argument("--out", required=True, help="engagement output dir to verify")
    ap.add_argument("--json", action="store_true", dest="as_json", help="machine-readable output")
    args = ap.parse_args()

    if args.review:
        review_path = Path(args.review)
    elif args.skill:
        review_path = Path(args.skill) / "review.md"
    else:
        ap.error("need --skill or --review")

    out = Path(args.out)
    manifest = load_manifest(review_path)

    results = []
    for a in manifest["artifacts"]:
        required = a.get("required", True)
        passed, detail = check_artifact(a, out)
        results.append({"id": a.get("id"), "path": a.get("path"),
                        "required": required, "passed": passed, "detail": detail})

    failed_required = [r for r in results if r["required"] and not r["passed"]]

    if args.as_json:
        print(json.dumps({"skill": manifest.get("skill"), "out": str(out),
                          "pass": not failed_required, "results": results}, indent=2))
    else:
        print(f"# Completion review -- {manifest.get('skill', '?')}  (out: {out})")
        for r in results:
            box = "x" if r["passed"] else " "
            opt = "" if r["required"] else "  (optional)"
            print(f"- [{box}] {r['id']}  {r['path']}{opt}  -- {r['detail']}")
        verdict = "PASS" if not failed_required else "FAIL"
        passed_n = len(results) - len(failed_required)
        print(f"\n{verdict}: {passed_n}/{len(results)} checks; "
              f"{len(failed_required)} required failure(s).")
        if failed_required:
            print("Any failed box => re-run that step (see checklist.md).")

    sys.exit(0 if not failed_required else 2)


if __name__ == "__main__":
    main()
