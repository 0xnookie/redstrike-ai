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
  python verify_completion.py --engagement engagements/<client>-<date>   # consolidated mode

Consolidated (`--engagement`) mode validates an orchestrator-led engagement that keeps ONE shared
findings.json + a single evidence vault (findings/evidence|poc/) + reviews/<id>.verdict.json, instead of
the per-skill OUT scaffolding above. It is the deterministic altitude for that layout: every finding must
cite at least one evidence artifact that actually exists and is non-empty (the pre-review hygiene lint), and
it soft-warns on CVSS/severity drift (via scripts/cvss.py) and missing reviewer verdicts.
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
    # a jsonl declared allow_empty may legitimately be 0 bytes (e.g. async callbacks not in yet)
    jsonl_empty_ok = typ == "jsonl" and a.get("allow_empty", False)
    min_bytes = a.get("min_bytes", 0 if jsonl_empty_ok else 1)

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
            sch = a.get("schema")
            if sch:
                ok, note = _validate_against_schema(data, sch)
                if not ok:
                    return False, f"{rel} fails schema {sch}: {note}"
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


_RS_ID_RE = re.compile(r"^RS-[0-9]{4}-[0-9]{3,}$")
_REQUIRED_FINDING_FIELDS = ("id", "title", "asset", "category", "severity",
                            "confidence", "status", "evidence", "reproduction")
_REVIEWED_STATUSES = {"verified", "rejected", "remediated"}


def _repo_root() -> Path:
    # skills/_contract/verify_completion.py -> repo root is two levels up.
    return Path(__file__).resolve().parents[2]


def _validate_against_schema(data, schema_rel: str):
    """Best-effort JSON-Schema validation for an artifact that declares `schema`.
    Returns (ok, note). Degrades gracefully: a missing schema file or a missing
    `jsonschema` dependency SKIPS (ok=True) rather than failing the gate, so CI
    without the dep still runs; a real schema violation FAILS (ok=False)."""
    schema_path = _repo_root() / schema_rel
    if not schema_path.is_file():
        return True, f"schema {schema_rel} not found (skipped)"
    try:
        import jsonschema  # type: ignore
    except ImportError:
        return True, "jsonschema not installed (skipped)"
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.validate(data, schema)
    except jsonschema.ValidationError as e:  # type: ignore
        loc = "/".join(str(x) for x in e.absolute_path) or "<root>"
        return False, f"{e.message} (at {loc})"
    except Exception as e:  # malformed schema etc. — don't block the gate
        return True, f"schema check error: {e} (skipped)"
    return True, "schema ok"


def _try_import_cvss():
    try:
        sys.path.insert(0, str(_repo_root() / "scripts"))
        import cvss  # type: ignore
        return cvss
    except Exception:
        return None


def _scope_text(eng: Path) -> str:
    sp = eng / "scope.yaml"
    return sp.read_text(encoding="utf-8", errors="replace") if sp.is_file() else ""


def _try_import_coverage():
    # import scripts/coverage.py by PATH (not name) so the pip 'coverage' package can't shadow it
    try:
        import importlib.util
        p = _repo_root() / "scripts" / "coverage.py"
        if not p.is_file():
            return None
        spec = importlib.util.spec_from_file_location("rs_coverage", p)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


def _coverage_warnings(eng: Path) -> list:
    """Soft, non-fatal coverage-ledger check folded into the engagement gate. The hard gate is the
    dedicated `scripts/coverage.py --validate`; here a gap is surfaced as a warning only."""
    cov = _try_import_coverage()
    if not cov:
        return []
    try:
        m = cov.load_map()
    except SystemExit:
        return []
    if not (eng / "coverage_ledger.json").is_file():
        return ["no coverage_ledger.json — category coverage untracked "
                "(run scripts/coverage.py --plan --engagement <dir>)"]
    try:
        ok, _lines, msgs = cov.validate(eng, m, strict=False)
    except Exception:
        return []
    if not ok:
        return [f"coverage: {msg}" for msg in msgs if not str(msg).startswith("no coverage_ledger")]
    return []


def _asset_host(asset: str) -> str:
    """Best-effort registrable host from an asset URL/endpoint (for a soft scope check)."""
    s = re.sub(r"^[a-z]+://", "", str(asset)).strip()
    s = s.split("/", 1)[0]          # drop path
    s = s.split("@")[-1]            # drop any userinfo
    s = s.split(":", 1)[0]          # drop port
    return s.lower()


def check_finding(f: dict, eng: Path, scope_text: str, cvss_mod, verdict_ids: set):
    """Return (hard_ok: bool, detail: str, warnings: list[str]) for one finding."""
    warns = []
    fid = f.get("id", "<no-id>")

    missing = [k for k in _REQUIRED_FINDING_FIELDS if k not in f or f.get(k) in (None, "", [], {})]
    if missing:
        return False, f"missing required field(s): {', '.join(missing)}", warns

    if not _RS_ID_RE.match(str(fid)):
        warns.append(f"{fid}: id does not match RS-YYYY-NNN")

    ev = f.get("evidence") or []
    if not isinstance(ev, list) or not ev:
        return False, "no evidence items", warns
    for i, item in enumerate(ev, 1):
        ref = (item or {}).get("ref")
        if not ref:
            return False, f"evidence #{i} has no ref", warns
        p = eng / ref
        if not p.is_file():
            return False, f"evidence #{i} ref not found: {ref}", warns
        if p.stat().st_size == 0:
            return False, f"evidence #{i} is 0 bytes (hygiene): {ref}", warns

    repro = f.get("reproduction") or []
    if not isinstance(repro, list) or not repro:
        return False, "reproduction steps missing", warns

    # --- soft checks (warnings only) ---
    if cvss_mod and f.get("cvss_vector"):
        try:
            score, rating, _ = cvss_mod.score_vector(f["cvss_vector"])
            declared = str(f.get("severity", "")).lower()
            if rating.lower() != declared and not f.get("potential_severity"):
                warns.append(f"{fid}: severity '{declared}' != CVSS rating "
                             f"'{rating.lower()}' ({score}); set potential_severity or fix the vector")
        except Exception as e:
            warns.append(f"{fid}: cvss_vector not scorable ({e})")

    if scope_text:
        host = _asset_host(f.get("asset", ""))
        root = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
        if host and host not in scope_text and root not in scope_text:
            warns.append(f"{fid}: asset host '{host}' not found in scope.yaml (verify scope)")

    status = f.get("status")
    has_review = isinstance(f.get("review"), dict) and f["review"].get("verdict")
    if status in _REVIEWED_STATUSES and not has_review and fid not in verdict_ids:
        warns.append(f"{fid}: status '{status}' but no review block and no reviews/{fid}.verdict.json")

    return True, f"{len(ev)} evidence artifact(s) ok", warns


def validate_engagement(eng: Path, as_json: bool) -> bool:
    fj = eng / "findings.json"
    reviews_dir = eng / "reviews"
    cvss_mod = _try_import_cvss()
    scope_text = _scope_text(eng)
    top_warnings = []
    if not scope_text:
        top_warnings.append("scope.yaml absent — scope compliance cannot be auto-checked (flagged, not failed)")
    top_warnings.extend(_coverage_warnings(eng))

    if not fj.is_file():
        msg = f"no findings.json at {fj}"
        print(json.dumps({"engagement": str(eng), "pass": False, "error": msg}) if as_json else f"[!] {msg}")
        return False
    try:
        findings = json.loads(fj.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        msg = f"findings.json invalid JSON: {e}"
        print(json.dumps({"engagement": str(eng), "pass": False, "error": msg}) if as_json else f"[!] {msg}")
        return False
    if not isinstance(findings, list):
        msg = "findings.json is not a JSON array"
        print(json.dumps({"engagement": str(eng), "pass": False, "error": msg}) if as_json else f"[!] {msg}")
        return False

    verdict_ids = {p.stem.replace(".verdict", "")
                   for p in reviews_dir.glob("*.verdict.json")} if reviews_dir.is_dir() else set()

    results = []
    for f in findings:
        ok, detail, warns = check_finding(f, eng, scope_text, cvss_mod, verdict_ids)
        results.append({"id": f.get("id"), "severity": f.get("severity"),
                        "status": f.get("status"), "passed": ok, "detail": detail, "warnings": warns})

    # evidence-vault hygiene: non-empty files nothing references
    referenced = {str((eng / (item or {}).get("ref", "")).resolve())
                  for f in findings for item in (f.get("evidence") or []) if (item or {}).get("ref")}
    orphans = []
    for sub in ("findings/evidence", "findings/poc"):
        d = eng / sub
        if d.is_dir():
            for p in d.rglob("*"):
                if p.is_file() and p.stat().st_size > 0 and str(p.resolve()) not in referenced:
                    orphans.append(str(p.relative_to(eng)))

    # recall audit: open-proof-gaps are real-looking findings dropped ONLY for lack of proof — keep visible
    opgaps = []
    reviews_dir2 = eng / "reviews"
    for f in findings:
        rc = (f.get("review") or {}).get("rejection_class")
        if rc is None and reviews_dir2.is_dir():
            vp = reviews_dir2 / f"{f.get('id')}.verdict.json"
            if vp.is_file():
                try:
                    rc = (json.loads(vp.read_text(encoding="utf-8")) or {}).get("rejection_class")
                except json.JSONDecodeError:
                    rc = None
        if rc == "open-proof-gap":
            opgaps.append(f.get("id"))
    if opgaps:
        shown = ", ".join(str(x) for x in opgaps[:5]) + ("…" if len(opgaps) > 5 else "")
        top_warnings.append(f"recall audit: {len(opgaps)} open-proof-gap finding(s) ({shown}) — "
                            "real-looking but unproven here; report as caveats / recall re-run candidates, "
                            "not silent drops")

    failed = [r for r in results if not r["passed"]]
    all_warnings = top_warnings + [w for r in results for w in r["warnings"]]

    if as_json:
        print(json.dumps({"engagement": str(eng), "pass": not failed,
                          "findings_checked": len(results), "failed": len(failed),
                          "results": results, "warnings": all_warnings,
                          "unreferenced_evidence": orphans, "cvss_available": bool(cvss_mod)}, indent=2))
    else:
        print(f"# Engagement review -- {eng}")
        for r in results:
            box = "x" if r["passed"] else " "
            print(f"- [{box}] {r['id']}  [{r['severity']}/{r['status']}]  -- {r['detail']}")
        if all_warnings:
            print("\n⚠ warnings (non-failing):")
            for w in all_warnings:
                print(f"  - {w}")
        if orphans:
            print(f"\nℹ {len(orphans)} non-empty evidence file(s) not referenced by any finding "
                  f"(e.g. {orphans[0]})")
        if not cvss_mod:
            print("\nℹ scripts/cvss.py not importable — CVSS/severity drift check skipped")
        verdict = "PASS" if not failed else "FAIL"
        print(f"\n{verdict}: {len(results) - len(failed)}/{len(results)} finding(s) pass hard checks; "
              f"{len(failed)} failure(s), {len(all_warnings)} warning(s).")
        if failed:
            print("A failed finding is missing a required field or cites missing/empty evidence => fix before reporting.")
    return not failed


def main() -> None:
    ap = argparse.ArgumentParser(description="Redstrike mechanical completion gate.")
    ap.add_argument("--skill", help="skill dir containing review.md")
    ap.add_argument("--review", help="path to review.md (overrides --skill)")
    ap.add_argument("--out", help="engagement output dir to verify (per-skill mode)")
    ap.add_argument("--engagement", help="engagement dir for consolidated-layout validation")
    ap.add_argument("--json", action="store_true", dest="as_json", help="machine-readable output")
    args = ap.parse_args()

    if args.engagement:
        ok = validate_engagement(Path(args.engagement), args.as_json)
        sys.exit(0 if ok else 2)

    if not args.out:
        ap.error("--out is required in per-skill mode (or use --engagement)")

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
    passed = [r for r in results if r["passed"]]
    optional_failed = [r for r in results if not r["required"] and not r["passed"]]

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
        tail = f"; {len(optional_failed)} optional skipped" if optional_failed else ""
        print(f"\n{verdict}: {len(passed)}/{len(results)} passed; "
              f"{len(failed_required)} required failure(s){tail}.")
        if failed_required:
            print("Any failed box => re-run that step (see checklist.md).")

    sys.exit(0 if not failed_required else 2)


if __name__ == "__main__":
    main()
