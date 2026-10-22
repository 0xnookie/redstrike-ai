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

Consolidated (`--engagement`) mode validates an orchestrator-led engagement regardless of which layout
it uses — it discovers findings from `<eng>/findings.json` (single shared vault), else the union of
`<eng>/*/findings.json` (the per-skill executor layout), else `<eng>/report/findings_consolidated.json`
(reporting output). For every finding it HARD-fails on a missing required field, missing/empty evidence,
or a finding/`review{}` schema violation (enum + additionalProperties, validated against finding.schema.json
via `jsonschema` when present, else a stdlib subset validator), and soft-warns on CVSS/severity drift
(via scripts/cvss.py), out-of-scope assets, and missing reviewer verdicts.
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


def _stdlib_schema_errors(data, schema, root=None, path="<root>"):
    """A tiny, dependency-free JSON-Schema *subset* validator used when the
    `jsonschema` package isn't installed. It covers exactly the constraints the
    Redstrike schemas rely on — $ref (local #/$defs/...), type, enum, required,
    properties, items, anyOf, and `additionalProperties` (both `false` and a
    sub-schema). Patterns/formats are intentionally NOT enforced (not the source
    of the defects this guards). Returns a list of human-readable error strings."""
    if root is None:
        root = schema
    errs = []
    if not isinstance(schema, dict):
        return errs
    if "$ref" in schema:
        target = root
        for part in schema["$ref"].lstrip("#/").split("/"):
            if part:
                target = (target or {}).get(part, {})
        return _stdlib_schema_errors(data, target, root, path)
    if "anyOf" in schema:
        if not any(not _stdlib_schema_errors(data, s, root, path) for s in schema["anyOf"]):
            errs.append(f"{path}: does not satisfy anyOf")
        return errs
    if "enum" in schema and data not in schema["enum"]:
        errs.append(f"{path}: {data!r} not one of {schema['enum']}")
    t = schema.get("type")
    if t == "array" or (t is None and "items" in schema):
        if not isinstance(data, list):
            return errs + [f"{path}: expected array"]
        items = schema.get("items")
        if isinstance(items, dict):
            for i, el in enumerate(data):
                errs += _stdlib_schema_errors(el, items, root, f"{path}[{i}]")
        return errs
    if t == "object" or "properties" in schema or "required" in schema:
        if not isinstance(data, dict):
            return errs + [f"{path}: expected object"]
        props = schema.get("properties", {})
        for req in schema.get("required", []):
            if req not in data:
                errs.append(f"{path}: missing required '{req}'")
        ap = schema.get("additionalProperties", True)
        for k, v in data.items():
            if k in props:
                errs += _stdlib_schema_errors(v, props[k], root, f"{path}/{k}")
            elif ap is False:
                errs.append(f"{path}: unexpected property '{k}'")
            elif isinstance(ap, dict):
                errs += _stdlib_schema_errors(v, ap, root, f"{path}/{k}")
    return errs


def _validate_against_schema(data, schema_rel: str):
    """Best-effort JSON-Schema validation for an artifact that declares `schema`.
    Returns (ok, note). Prefers the `jsonschema` package; falls back to a stdlib
    subset validator (`_stdlib_schema_errors`) so a real violation still FAILS even
    without the dependency. A missing schema file SKIPS (ok=True)."""
    schema_path = _repo_root() / schema_rel
    if not schema_path.is_file():
        return True, f"schema {schema_rel} not found (skipped)"
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except Exception as e:  # malformed schema — don't block the gate
        return True, f"schema unreadable: {e} (skipped)"
    try:
        import jsonschema  # type: ignore
        try:
            jsonschema.validate(data, schema)
        except jsonschema.ValidationError as e:  # type: ignore
            loc = "/".join(str(x) for x in e.absolute_path) or "<root>"
            return False, f"{e.message} (at {loc})"
        return True, "schema ok"
    except ImportError:
        errs = _stdlib_schema_errors(data, schema)
        if errs:
            return False, "; ".join(errs[:4]) + (" …" if len(errs) > 4 else "") + " (stdlib check)"
        return True, "schema ok (stdlib check)"
    except Exception as e:
        return True, f"schema check error: {e} (skipped)"


def _finding_schema_def():
    """Return the single-finding sub-schema ($defs/finding) + the full root schema,
    or (None, None) if unavailable. Cached on the function object."""
    cache = getattr(_finding_schema_def, "_cache", False)
    if cache is not False:
        return cache
    result = (None, None)
    sp = _repo_root() / "skills" / "_contract" / "finding.schema.json"
    if sp.is_file():
        try:
            root = json.loads(sp.read_text(encoding="utf-8"))
            result = (root.get("$defs", {}).get("finding"), root)
        except Exception:
            result = (None, None)
    _finding_schema_def._cache = result
    return result


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

    # schema conformance (enums + review-block additionalProperties/enums) — HARD.
    # This is the altitude that catches reviewer-written `review{}` defects
    # (stray keys, bad confidence/verdict/rubric enums) the per-skill gate can't see.
    fdef, froot = _finding_schema_def()
    if fdef:
        try:
            import jsonschema  # type: ignore
            try:
                jsonschema.validate(f, {**froot, **fdef})  # validate as a finding object
                serrs = []
            except jsonschema.ValidationError as e:  # type: ignore
                serrs = [f"{'/'.join(str(x) for x in e.absolute_path) or '<finding>'}: {e.message}"]
        except ImportError:
            serrs = _stdlib_schema_errors(f, fdef, froot, path=fid)
        if serrs:
            return False, "schema violation: " + "; ".join(serrs[:4]) + (" …" if len(serrs) > 4 else ""), warns

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


def _load_findings_array(path: Path):
    """Load a findings file as a flat list. Accepts a bare array, or a reporting
    object {findings:[...], attack_chains:[...]}. Returns None on parse failure."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return list(data.get("findings") or []) + list(data.get("attack_chains") or [])
    return None


def _discover_engagement_findings(eng: Path):
    """Find the engagement's findings across the layouts the framework actually
    produces, in priority order:
      1. <eng>/findings.json                     (single shared-vault layout)
      2. union of <eng>/*/findings.json          (per-skill executor layout — the common case)
      3. <eng>/report/findings_consolidated.json (reporting output; may be {findings, attack_chains})
    Returns (findings_list, source_description) or (None, reason)."""
    root_fj = eng / "findings.json"
    if root_fj.is_file():
        arr = _load_findings_array(root_fj)
        return (arr, "findings.json") if arr is not None else (None, f"{root_fj} is not a findings array")

    per = sorted(p for p in eng.glob("*/findings.json"))
    if per:
        findings = []
        bad = []
        for p in per:
            arr = _load_findings_array(p)
            if arr is None:
                bad.append(str(p.relative_to(eng)))
            else:
                findings.extend(arr)
        if bad:
            return None, "invalid JSON in: " + ", ".join(bad)
        return findings, f"{len(per)} per-skill findings.json file(s)"

    cons = eng / "report" / "findings_consolidated.json"
    if cons.is_file():
        arr = _load_findings_array(cons)
        return (arr, "report/findings_consolidated.json") if arr is not None else (None, f"{cons} unparseable")

    return None, "no findings.json (root, per-skill, or report/findings_consolidated.json)"


def _collect_verdict_ids(eng: Path) -> set:
    """Reviewer verdict ids from the root vault AND every per-skill reviews/ dir."""
    ids = set()
    for rd in [eng / "reviews"] + list(eng.glob("*/reviews")):
        if rd.is_dir():
            ids |= {p.stem.replace(".verdict", "") for p in rd.glob("*.verdict.json")}
    return ids


def validate_engagement(eng: Path, as_json: bool) -> bool:
    cvss_mod = _try_import_cvss()
    scope_text = _scope_text(eng)
    top_warnings = []
    if not scope_text:
        top_warnings.append("scope.yaml absent — scope compliance cannot be auto-checked (flagged, not failed)")
    top_warnings.extend(_coverage_warnings(eng))
    if not any(eng.rglob("host_discovery.json")):
        top_warnings.append("no host_discovery.json — recon's structured host/port map wasn't persisted; "
                            "the console's Ports view will be empty (Assets falls back to scope+findings). "
                            "Run host-discovery / emit <eng>/host-discovery/host_discovery.json.")

    findings, source = _discover_engagement_findings(eng)
    if findings is None:
        print(json.dumps({"engagement": str(eng), "pass": False, "error": source}) if as_json else f"[!] {source}")
        return False
    if not as_json:
        top_warnings.append(f"findings source: {source} ({len(findings)} finding(s))")

    verdict_ids = _collect_verdict_ids(eng)

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
