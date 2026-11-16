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

It also enforces the INDEPENDENT-REVIEW gate (#1): once a report exists, every finding that reaches
reporting (verdict accepted/blocked) must have been reviewed by a real independent `<class>-verify` agent.
A finding "verified" only by the orchestrator/executor itself ('orchestrator-self-verify', a human, blank,
or any non-roster name) HARD-fails unless an explicit operator-accept is recorded in
`<eng>/reviews/self_verified_accepts.json` ({"RS-...": "why no reviewer covers this class"}) — so
self-attestation is never a silent pass, and the missing reviewer class is named for backfill.
"""
import argparse
import glob as globmod
import json
import os
import re
import sys
from collections import Counter
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
# statuses that imply review already happened (the lifecycle axis) — used ONLY to flag a finding that
# claims a reviewed status but carries no review.verdict record. `review.verdict` is the authoritative
# axis; `status` is derived from it (see verify-base.md "Two axes").
_REVIEWED_STATUSES = {"verified", "rejected", "remediated"}

# Post-exploitation / persistence classes that PLANT or MODIFY state and must prove benign reversion.
# Conservative on purpose (the task's scope): persistence + the AD/credential post-ex classes. A finding
# from one of these REQUIRES a verified `cleanup` object (see finding.schema.json). Detected by the
# producing skill (per-skill layout tags it); a consolidated report loses the tag, and the per-skill
# mechanical gate + verify.md already enforce cleanup.md upstream there.
_CLEANUP_REQUIRED_SKILLS = {
    "persistence", "credential-access",
    "ad-initial-access", "ad-kerberos", "ad-acl-abuse", "ad-adcs", "ad-lateral-movement",
    "sccm-exploitation",
}


def _requires_cleanup(f: dict) -> bool:
    """True iff this finding came from a post-ex/persistence class that plants/modifies state and so must
    carry a verified reversion record. Keyed on the producing skill (zero false positives on web findings)."""
    return f.get("_rs_source_skill") in _CLEANUP_REQUIRED_SKILLS


def _repo_root() -> Path:
    # skills/_contract/verify_completion.py -> repo root is two levels up.
    return Path(__file__).resolve().parents[2]


def _stdlib_schema_errors(data, schema, root=None, path="<root>"):
    """A tiny, dependency-free JSON-Schema *subset* validator used when the
    `jsonschema` package isn't installed. It covers exactly the constraints the
    Redstrike schemas rely on — $ref (local #/$defs/...), type, enum, required,
    properties, items, anyOf, `additionalProperties` (both `false` and a
    sub-schema), and the scalar/array bounds the schemas declare: `pattern`,
    `minLength`/`maxLength`, `minItems`/`maxItems`, `minimum`/`maximum`. Only
    `format` is left advisory (jsonschema doesn't enforce it by default either),
    so this covers the real constraints even when jsonschema is absent.
    Returns a list of human-readable error strings."""
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
    if isinstance(data, str):
        pat = schema.get("pattern")
        if pat is not None and re.search(pat, data) is None:
            errs.append(f"{path}: {data!r} does not match pattern {pat!r}")
        if isinstance(schema.get("minLength"), int) and len(data) < schema["minLength"]:
            errs.append(f"{path}: string shorter than minLength {schema['minLength']}")
        if isinstance(schema.get("maxLength"), int) and len(data) > schema["maxLength"]:
            errs.append(f"{path}: string longer than maxLength {schema['maxLength']}")
    elif isinstance(data, (int, float)) and not isinstance(data, bool):
        if isinstance(schema.get("minimum"), (int, float)) and data < schema["minimum"]:
            errs.append(f"{path}: {data} below minimum {schema['minimum']}")
        if isinstance(schema.get("maximum"), (int, float)) and data > schema["maximum"]:
            errs.append(f"{path}: {data} above maximum {schema['maximum']}")
    t = schema.get("type")
    if t == "array" or (t is None and "items" in schema):
        if not isinstance(data, list):
            return errs + [f"{path}: expected array"]
        if isinstance(schema.get("minItems"), int) and len(data) < schema["minItems"]:
            errs.append(f"{path}: array has {len(data)} item(s), need >= {schema['minItems']}")
        if isinstance(schema.get("maxItems"), int) and len(data) > schema["maxItems"]:
            errs.append(f"{path}: array has {len(data)} item(s), max {schema['maxItems']}")
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


def _report_present(eng: Path) -> bool:
    """A consolidated report means the engagement is claiming DONE (reporting ran)."""
    return (eng / "report" / "findings_consolidated.json").is_file()


# --- engagement diagnostics (Phase-2 consumer of runtime/diagnostics.json) ----------------------- #
# runtime/diagnostics.json is produced per-engagement by the run engine (its schema lives in
# skills/_contract/diagnostics.schema.json, owned elsewhere — referenced read-only here). We CONSUME
# its latest run to make "we were blocked / produced nothing" visible and gated, not left to the model:
#   (a) AUTO-POPULATE — a transport-`blocked` host flips its web coverage categories to `blocked`, so a
#       clean-looking clear on a WAF-blocked host is attributed to the block deterministically.
#   (b) HARD GATE — a zero-finding report must prove it was a real clean test (an explained outcome),
#       never a silent empty (empty ≠ clean).

def _load_diagnostics(eng: Path):
    """Parse runtime/diagnostics.json (the per-engagement health log), or None when absent/invalid."""
    p = eng / "runtime" / "diagnostics.json"
    if not p.is_file():
        return None
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — a half-written health log must never crash the gate
        return None
    return d if isinstance(d, dict) else None


def _latest_run(diag):
    """The latest runs[] entry (the contract says: use the last one), or None."""
    if not isinstance(diag, dict):
        return None
    runs = diag.get("runs")
    if not isinstance(runs, list) or not runs:
        return None
    last = runs[-1]
    return last if isinstance(last, dict) else None


def _transport_blocked_hosts(run):
    """[(host, block_rate, waf), ...] for every transport_health host classified 'blocked' in this run,
    worst (highest block_rate) first. [] when transport health is absent/healthy."""
    if not isinstance(run, dict):
        return []
    th = run.get("transport_health")
    hosts = th.get("hosts") if isinstance(th, dict) else None
    out = []
    if isinstance(hosts, list):
        for h in hosts:
            if isinstance(h, dict) and h.get("classification") == "blocked":
                try:
                    rate = float(h.get("block_rate") or 0)
                except (TypeError, ValueError):
                    rate = 0.0
                out.append((str(h.get("host") or "?"), rate, h.get("waf")))
    out.sort(key=lambda t: t[1], reverse=True)
    return out


def _transport_reason(host, rate, waf) -> str:
    """The coverage-ledger reason for a transport-blocked category — sourced from transport health."""
    waf_s = str(waf).strip() if waf else "WAF unidentified"
    return f"transport: WAF block_rate {rate:.0%} on {host} ({waf_s})"


# Coverage categories eligible for the transport-blocked auto-mark: a routed web class that never ran
# (`pending`) or ran clean (`attempted`, 0 findings). A class WITH findings got through the block;
# `skipped`/`n/a`/`pipeline` were a deliberate route decision a transport block doesn't change.
_TRANSPORT_BLOCK_PHASES = {"web"}


def _auto_populate_blocked_coverage(eng: Path) -> list:
    """AUTO-POPULATE (reliability): when the latest diagnostics run shows a transport-`blocked` host,
    mark the engagement's web coverage categories still `pending` or `attempted`-empty as `blocked`
    with a transport-sourced reason — so a clean-looking clear on a WAF-blocked host is attributed to
    the block deterministically, NOT left to the model to notice. Mutates coverage_ledger.json in place
    (atomic, via coverage.py's writer so the ledger stays single-owner). Returns the flipped category
    ids (surfaced as a warning). No-op without diagnostics / a blocked host / the ledger / coverage.py."""
    blocked = _transport_blocked_hosts(_latest_run(_load_diagnostics(eng)))
    if not blocked:
        return []
    ledger_path = eng / "coverage_ledger.json"
    if not ledger_path.is_file():
        return []
    try:
        led = json.loads(ledger_path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return []
    cats = led.get("categories")
    if not isinstance(cats, list):
        return []
    host, rate, waf = blocked[0]  # worst host for the reason; the mark covers the web surface
    reason = _transport_reason(host, rate, waf)
    flipped = []
    for c in cats:
        if not isinstance(c, dict) or c.get("phase") not in _TRANSPORT_BLOCK_PHASES:
            continue
        st = c.get("status")
        empty_clear = st == "attempted" and not (c.get("findings_count") or 0)
        if st == "pending" or empty_clear:
            c["status"] = "blocked"
            c["reason"] = reason
            flipped.append(c.get("id"))
    if not flipped:
        return []
    payload = json.dumps(led, indent=2) + "\n"
    cov = _try_import_coverage()  # reuse its atomic ledger writer (ledger stays single-owner)
    try:
        if cov is not None and hasattr(cov, "atomic_write"):
            cov.atomic_write(ledger_path, payload)
        else:
            ledger_path.write_text(payload, encoding="utf-8")
    except Exception:  # noqa: BLE001
        return []
    return flipped


def _reportable_findings_count(eng: Path, findings: list) -> int:
    """Findings that reach the report (effective verdict accepted/blocked, non-composite) — mirrors the
    reporting skill's `_reportable`, so 'zero-finding' here means exactly what the report means."""
    n = 0
    for f in findings:
        if not isinstance(f, dict) or f.get("composite") or f.get("_composite"):
            continue
        verdict, _ = _review_of(f, eng)
        if verdict in ("accepted", "blocked"):
            n += 1
    return n


def _diagnostics_hard_errors(eng: Path, findings: list) -> list:
    """HARD diagnostics gate (reliability) — active once a report exists AND it carries ZERO reportable
    findings. An empty report must PROVE it was a real clean test, not a silent 'we were blocked /
    produced nothing'. The latest diagnostics run must carry an EXPLAINED outcome: `clean-tested`, or
    `degraded-empty`/`failed` WITH a `degraded_reason`. A missing diagnostics file, a missing/contradictory
    outcome, or an unexplained empty HARD-fails (empty ≠ clean). [] when no report, or the report has
    reportable findings (then the diagnostics gate does not apply)."""
    if not _report_present(eng):
        return []
    if _reportable_findings_count(eng, findings) > 0:
        return []
    run = _latest_run(_load_diagnostics(eng))
    pre = ("diagnostics gate (zero-finding report → the latest runtime/diagnostics.json run must carry an "
           "explained outcome): ")
    if run is None:
        return [pre + "no runtime/diagnostics.json with a runs[] entry — an empty report cannot prove it was "
                "a real clean test rather than a silent block/failure (empty ≠ clean). Emit "
                "runtime/diagnostics.json recording the run's outcome."]
    outcome = run.get("outcome")
    reason = str(run.get("degraded_reason") or "").strip()
    if outcome == "clean-tested":
        return []
    if outcome in ("degraded-empty", "failed"):
        if reason:
            return []
        return [pre + f"latest run outcome is '{outcome}' but degraded_reason is empty — an unexplained empty "
                "is not a clean result (empty ≠ clean). Record why the run produced nothing."]
    shown = repr(outcome) if outcome is not None else "missing"
    return [pre + f"latest run outcome is {shown}, which does not explain an empty report — set it to "
            "'clean-tested' (a genuine clean run), or to 'degraded-empty'/'failed' with a degraded_reason "
            "(empty ≠ clean)."]


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


def _coverage_hard_errors(eng: Path) -> list:
    """HARD coverage gate — only active once a consolidated report exists.

    While the hunt is in progress, coverage gaps are legitimately open and stay a warning (above).
    But once `report/findings_consolidated.json` exists the engagement is claiming to be finished,
    and a report cannot honestly coexist with routed-but-never-run vuln classes or an untracked
    ledger (the juice-shop-2026-10-20 failure: XSS/auth/XXE never ran, clean report anyway). At that
    point a MISSING ledger (strict) or any `pending`/absent category is a FAIL, not a warning.

    Returns [] when no report is present (hunting phase) or coverage can't be checked (surfaced
    elsewhere — don't fabricate a failure)."""
    if not _report_present(eng):
        return []
    cov = _try_import_coverage()
    if not cov:
        return []
    try:
        m = cov.load_map()
    except (SystemExit, Exception):  # noqa: BLE001
        return []
    try:
        ok, _lines, msgs = cov.validate(eng, m, strict=True)
    except Exception:  # noqa: BLE001
        return []
    if ok:
        return []
    return [f"coverage gate (report present → ledger must be complete): {msg}" for msg in msgs]


def _try_import_surface():
    try:
        import importlib.util
        p = _repo_root() / "scripts" / "surface.py"
        if not p.is_file():
            return None
        spec = importlib.util.spec_from_file_location("rs_surface", p)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


def _surface_hard_errors(eng: Path) -> list:
    """HARD surface gate (fix #5, strict since fix: universal emission) — active once a report exists.

    A report must not ship with surface recon discovered but no executor tested (the leak category
    coverage can't see). Now that the recon feeders emit the ledger universally and `surface.py --plan`
    is idempotent, a MISSING ledger at report time is itself a FAIL (not a warning) — it means surface
    coverage was never tracked, the juice-shop-2026-10-20 blind spot. A PRESENT ledger is validated
    STRICT, so an empty-but-present ledger (feeders didn't populate it) also fails. Mirrors how
    `_coverage_hard_errors` treats a missing/incomplete coverage ledger at report time."""
    if not _report_present(eng):
        return []
    if not (eng / "surface_ledger.json").is_file():
        return ["surface gate (report present → a surface ledger is required): no surface_ledger.json — "
                "surface coverage was never tracked (run scripts/surface.py --plan --engagement <dir> "
                "after recon; it is idempotent and safe to re-run)"]
    sf = _try_import_surface()
    if not sf:
        return []
    try:
        led = json.loads((eng / "surface_ledger.json").read_text(encoding="utf-8"))
        ok, _lines, msgs = sf.validate(led, strict=True)
    except Exception:  # noqa: BLE001
        return []
    if ok:
        return []
    return [f"surface gate (report present → surface must be tested/accounted): {m}" for m in msgs]


def _surface_warnings(eng: Path) -> list:
    """Soft nudge DURING the hunt (no report yet): emit the surface ledger after recon so the
    report-time strict gate has something to check."""
    if not _report_present(eng) and not (eng / "surface_ledger.json").is_file():
        return ["no surface_ledger.json yet — emit it after recon (scripts/surface.py --plan "
                "--engagement <dir>); it becomes a hard gate once a report exists"]
    return []


def _try_import_notebook():
    try:
        import importlib.util
        p = _repo_root() / "scripts" / "notebook.py"
        if not p.is_file():
            return None
        spec = importlib.util.spec_from_file_location("rs_notebook", p)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["rs_notebook"] = mod
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


def _notebook_warnings(eng: Path) -> list:
    """SOFT, always (never a hard gate). The engagement notebook (leads + recon intel + evidence + RoE +
    test accounts) makes a zero-finding hunt legible — it is encouraged, not mandatory, so this only ever
    warns, even once a report exists. Validates the notebook when present; nudges to emit it when absent."""
    nb_path = eng / "notebook.json"
    if not nb_path.is_file():
        return ["no notebook.json — recon intel + leads aren't captured, so a zero-finding hunt looks "
                "empty in the console (run scripts/notebook.py --plan --engagement <dir>). Soft — never fails."]
    mod = _try_import_notebook()
    if not mod:
        return []
    try:
        nb = mod.load(eng)
        ok, msgs = mod.validate(nb, mod._finding_ids(eng))
        return [] if ok else [f"notebook.json: {m}" for m in msgs]
    except Exception:
        return []


def _try_import_reconverge():
    try:
        import importlib.util
        p = _repo_root() / "scripts" / "reconverge.py"
        if not p.is_file():
            return None
        spec = importlib.util.spec_from_file_location("rs_reconverge", p)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["rs_reconverge"] = mod  # dataclass-free, but keep the import self-consistent
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


def _reconverge_hard_errors(eng: Path) -> list:
    """HARD re-convergence gate (fix #6) — active only when a report AND a non-empty re-convergence
    inbox both exist. A report must not ship while mid-hunt discoveries (new signals/surface recorded
    in reconvergence/inbox.jsonl) remain un-routed — the single-pass leak. No inbox => no gate."""
    if not _report_present(eng):
        return []
    rc = _try_import_reconverge()
    if not rc:
        return []
    try:
        return rc.reconverge_hard_errors(eng)
    except Exception:  # noqa: BLE001
        return []


def _routing_signal_vocab() -> set:
    """The CLOSED signal vocabulary (routing-map.json `signals` keys). Empty => unreadable (gate skips)."""
    rm = _repo_root() / "skills" / "_contract" / "routing-map.json"
    try:
        return set((json.loads(rm.read_text(encoding="utf-8")).get("signals") or {}).keys())
    except Exception:  # noqa: BLE001
        return set()


def _surface_kind_enum() -> set:
    """The CLOSED surface-kind enum (surface_ledger.schema.json). Empty => unreadable (gate skips)."""
    sp = _repo_root() / "skills" / "_contract" / "surface_ledger.schema.json"
    try:
        s = json.loads(sp.read_text(encoding="utf-8"))
        kind = (((s.get("$defs") or {}).get("surface") or {}).get("properties") or {}).get("kind") or {}
        return set(kind.get("enum") or [])
    except Exception:  # noqa: BLE001
        return set()


def _followup_surface_kinds() -> set:
    """Recognized NON-testable 'follow-up' surface kinds (surface.FOLLOWUP_ROUTES; e.g. `content`). These are
    legitimate in the re-convergence inbox — a content sitemap/robots/API-schema discovery routed BACK to
    content-discovery for URL/object-ref extraction (fix #5) — so the inbox-integrity gate does NOT treat
    them as corruption. They are still NOT valid surface-LEDGER elements (the ledger stays strict)."""
    sf = _try_import_surface()
    try:
        return set(sf.FOLLOWUP_ROUTES) if sf else set()
    except Exception:  # noqa: BLE001
        return set()


def _coordination_integrity_errors(eng: Path) -> list:
    """HARD coordination-artifact integrity gate — active only once a report exists.

    The re-convergence inbox, the surface ledger and the coverage ledger are produced by the pipeline
    ITSELF, yet nothing validated their own vocabulary, so an out-of-vocab signal (`sink:dom-backlink`)
    and an out-of-enum surface kind (`content`) were silently folded in — where they route to nothing and
    mask a recall gap (the real false-negative this gate exists to stop). Once a report claims DONE this is
    a FAIL: inbox signals ⊄ the routing vocab, inbox/surface-ledger kinds ⊄ the enum, or
    coverage_ledger.signals_used ⊄ the vocab. Reads the RAW artifacts (so a fold-in cannot hide it).

    Returns [] when no report is present, or when the vocab/enum can't be read (surfaced elsewhere)."""
    if not _report_present(eng):
        return []
    vocab = _routing_signal_vocab()
    kinds = _surface_kind_enum()
    followups = _followup_surface_kinds()  # content & co. are legitimate inbox reroutes, not corruption (fix #5)
    errs = []

    inbox = eng / "reconvergence" / "inbox.jsonl"
    if inbox.is_file() and (vocab or kinds):
        bad_sig, bad_kind = set(), set()
        for ln in inbox.read_text(encoding="utf-8", errors="replace").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                rec = json.loads(ln)
            except json.JSONDecodeError:
                continue
            if not isinstance(rec, dict):
                continue
            if vocab:
                bad_sig |= {str(s) for s in (rec.get("signals") or []) if str(s) not in vocab}
            if kinds:
                bad_kind |= {str((it or {}).get("kind")) for it in (rec.get("surface") or [])
                             if (it or {}).get("kind") and (it or {}).get("kind") not in kinds
                             and (it or {}).get("kind") not in followups}
        if bad_sig:
            errs.append("coordination-integrity gate (report present): reconvergence/inbox.jsonl carries "
                        f"out-of-vocab signal(s) {sorted(bad_sig)} not in routing-map.json — quarantine them "
                        "(scripts/reconverge.py --apply writes reconvergence/inbox.rejected.jsonl), never fold them in")
        if bad_kind:
            errs.append("coordination-integrity gate (report present): reconvergence/inbox.jsonl carries "
                        f"out-of-enum surface kind(s) {sorted(bad_kind)} not in the surface-ledger kind enum")

    sl = eng / "surface_ledger.json"
    if sl.is_file() and kinds:
        try:
            led = json.loads(sl.read_text(encoding="utf-8"))
            bad = sorted({str(s.get("kind")) for s in (led.get("surfaces") or []) if s.get("kind") not in kinds})
        except Exception:  # noqa: BLE001
            bad = []
        if bad:
            errs.append("coordination-integrity gate (report present): surface_ledger.json has out-of-enum "
                        f"kind(s) {bad} — only {sorted(kinds)} are valid surface-ledger kinds")

    cl = eng / "coverage_ledger.json"
    if cl.is_file() and vocab:
        try:
            cov = json.loads(cl.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            cov = {}
        bad = sorted({str(s) for s in (cov.get("signals_used") or []) if str(s) not in vocab})
        if bad:
            errs.append("coordination-integrity gate (report present): coverage_ledger.json signals_used has "
                        f"out-of-vocab signal(s) {bad} not in routing-map.json (a folded-in invalid signal)")
        # triggers_matched is the OTHER place a coverage entry holds signals; a hand-edit / fold-in could slip
        # an out-of-vocab token in here too (routes to nothing, masks the real reason the category ran).
        bad_tm = sorted({str(s) for c in (cov.get("categories") or []) if isinstance(c, dict)
                         for s in (c.get("triggers_matched") or []) if str(s) not in vocab})
        if bad_tm:
            errs.append("coordination-integrity gate (report present): coverage_ledger.json triggers_matched has "
                        f"out-of-vocab signal(s) {bad_tm} not in routing-map.json (a folded-in invalid signal)")
    return errs


def _try_import_recall_audit():
    try:
        import importlib.util
        p = _repo_root() / "scripts" / "recall_audit.py"
        if not p.is_file():
            return None
        spec = importlib.util.spec_from_file_location("rs_recall_audit", p)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["rs_recall_audit"] = mod
        # recall_audit imports `escalation`; make sure scripts/ is importable for it
        sys.path.insert(0, str(_repo_root() / "scripts"))
        spec.loader.exec_module(mod)
        return mod
    except Exception:  # noqa: BLE001
        return None


# recall-audit gap types that make a clean-looking report untrustworthy (false-negative altitude). These
# are the HIGH gaps a report must not ship over: a class that ran-and-found-nothing on a signalled surface
# with the escalation ladder unexhausted (shallow-clear), a class skipped although a signal matched it
# (skipped-but-signalled), or a routed class that never ran (pending-at-close / never-run). `untested-surface`
# is already a hard gate (surface) and `weak-skip-reason`/`no-ledger` are covered elsewhere, so they stay
# advisory here to avoid double-failing.
_RECALL_GATED_TYPES = {"shallow-clear", "skipped-but-signalled", "pending-at-close", "never-run"}


def _recall_accepts(eng: Path) -> dict:
    """Operator acknowledgments that a recall gap may remain at report time because the clear is in fact
    trustworthy (or the class is out of scope for a stated reason). File:
    `<eng>/reviews/recall_audit_accepts.json`, either `{"<type>:<category>": "reason"}` (or a bare
    `"<category>"` to accept all its gated gaps), or `[{"id":"<type>:<cat>"|"<cat>", "reason":...}]`.
    Mirrors reviews/self_verified_accepts.json. Returns key→reason for every entry with a non-empty reason."""
    p = eng / "reviews" / "recall_audit_accepts.json"
    if not p.is_file():
        return {}
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}
    out = {}
    if isinstance(d, dict):
        for k, v in d.items():
            reason = v if isinstance(v, str) else (v.get("reason") if isinstance(v, dict) else "")
            if isinstance(reason, str) and reason.strip():
                out[str(k)] = reason.strip()
    elif isinstance(d, list):
        for e in d:
            if isinstance(e, dict) and e.get("id") and str(e.get("reason", "")).strip():
                out[str(e["id"])] = str(e["reason"]).strip()
    return out


def _recall_check(eng: Path) -> tuple:
    """(hard_errors, warnings) for the recall-audit gate. HARD only once a report exists: a gated recall
    gap (shallow-clear / skipped-but-signalled / never-run) must be closed (escalate + re-run the class) or
    explicitly accepted. An accepted gap is surfaced as a warning so the exception is never silent."""
    if not _report_present(eng):
        return [], []
    ra = _try_import_recall_audit()
    if not ra:
        return [], []
    try:
        res = ra.load_and_audit(eng)
    except Exception:  # noqa: BLE001
        return [], []
    accepts = _recall_accepts(eng)
    hard, warns = [], []
    for g in res.get("gaps", []):
        if g.get("type") not in _RECALL_GATED_TYPES:
            continue
        cat = g.get("category") or "?"
        gtype = g.get("type")
        keys = (f"{gtype}:{cat}", str(cat))
        reason = next((accepts[k] for k in keys if k in accepts), None)
        detail = g.get("detail") or ""
        if reason:
            warns.append(f"recall-audit gap operator-accepted: {cat} [{gtype}] — {reason} "
                         f"(backfill: escalate/run the class to remove this exception)")
        else:
            hard.append("recall-audit gate (report present → a shallow-clear/skipped-but-signalled/"
                        f"never-run gap must be closed or accepted): {cat} [{gtype}] — {detail}. "
                        f"Escalate + re-run the class, or record an accept in "
                        f"reviews/recall_audit_accepts.json (\"{gtype}:{cat}\": \"why this clear is trustworthy\")")
    return hard, warns


def _recall_hard_errors(eng: Path) -> list:
    """HARD recall-audit gate (named entry point; mirrors _coverage_hard_errors/_surface_hard_errors):
    the gated recall gaps a report must not ship over. [] when no report is present."""
    return _recall_check(eng)[0]


def _try_import_chain_validate():
    try:
        import importlib.util
        p = _repo_root() / "scripts" / "chain_validate.py"
        if not p.is_file():
            return None
        spec = importlib.util.spec_from_file_location("rs_chain_validate", p)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["rs_chain_validate"] = mod
        spec.loader.exec_module(mod)
        return mod
    except Exception:  # noqa: BLE001
        return None


def _chain_hard_errors(eng: Path) -> list:
    """HARD attack-chain gate (fix: no attack-chain validator) — active only once a report exists. Every
    chain step must resolve to an accepted/blocked finding, and every chain finding must be composite."""
    if not _report_present(eng):
        return []
    cv = _try_import_chain_validate()
    if not cv:
        return []
    try:
        return cv.chain_hard_errors(eng)
    except Exception:  # noqa: BLE001
        return []


def _duplicate_id_errors(eng: Path, findings: list) -> list:
    """HARD duplicate finding-id gate — active only once a consolidated report exists.

    Finding ids must be engagement-unique (RS-YYYY-NNN). While the hunt is in progress an id can
    legitimately be in flux, so this stays silent. But once `report/findings_consolidated.json` exists
    the engagement is claiming DONE, and a report cannot honestly ship with two findings sharing an id —
    aggregated across the per-skill */findings.json files, a collision silently collapses/confuses the
    consolidated report. Mirrors the coverage hard-gate: no report → no gate.

    Returns one error per duplicated id (with its occurrence count); [] when no report is present."""
    if not _report_present(eng):
        return []
    counts = Counter(f.get("id") for f in findings
                     if isinstance(f, dict) and f.get("id"))
    return [f"duplicate finding id '{fid}' appears {n}x across the engagement's findings "
            f"(ids must be engagement-unique)"
            for fid, n in sorted(counts.items()) if n > 1]


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
        # Validate a copy without the transient `_rs_*` discovery tags (the schema is additionalProperties:false).
        f_schema = {k: v for k, v in f.items() if not k.startswith("_rs_")}
        try:
            import jsonschema  # type: ignore
            try:
                jsonschema.validate(f_schema, {**froot, **fdef})  # validate as a finding object
                serrs = []
            except jsonschema.ValidationError as e:  # type: ignore
                serrs = [f"{'/'.join(str(x) for x in e.absolute_path) or '<finding>'}: {e.message}"]
        except ImportError:
            serrs = _stdlib_schema_errors(f_schema, fdef, froot, path=fid)
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

    # Cleanup/reversion gate (post-ex/persistence): a class that plants or modifies state must PROVE benign
    # reversion with a verified `cleanup` object, not prose. HARD for the conservative post-ex set.
    if _requires_cleanup(f):
        cu = f.get("cleanup")
        if not isinstance(cu, dict) or not cu:
            return False, (f"post-ex/persistence finding (source: {f.get('_rs_source_skill')}) lacks a verified "
                           "`cleanup` object (mechanism/removed/verified_by/ref) proving reversion"), warns
        miss = [k for k in ("mechanism", "removed", "verified_by", "ref") if k not in cu]
        empty = [k for k in ("mechanism", "verified_by", "ref") if k in cu and str(cu.get(k)).strip() == ""]
        if miss or empty:
            return False, f"cleanup object incomplete (missing: {miss or '—'}, empty: {empty or '—'})", warns
        if cu.get("removed") is not True:
            return False, "cleanup.removed is not true — reversion not verified (post-ex/persistence)", warns
        cp = eng / cu["ref"]
        if not cp.is_file():
            return False, f"cleanup ref not found: {cu['ref']}", warns
        if cp.stat().st_size == 0:
            return False, f"cleanup ref is 0 bytes: {cu['ref']}", warns

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
                # Tag each finding with its producing skill (the dir name) so the cleanup/reversion gate can
                # tell a post-ex/persistence finding from a web finding. Transient (`_rs_*`): stripped before
                # schema validation. Only present in the per-skill layout; a consolidated report loses it.
                for f in arr:
                    if isinstance(f, dict):
                        f.setdefault("_rs_source_skill", p.parent.name)
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


# --- independent-review gate (#1 — no report over self-attested findings) ----------------------- #
# Redstrike's core guarantee is that a reportable finding is gated by an INDEPENDENT `<class>-verify`
# reviewer (a candidate ≠ a finding; the reviewer, in its own fresh context, proves it). A finding that
# reaches reporting but was "reviewed" only by the orchestrator/executor itself (reviewer
# 'orchestrator-self-verify', a human, blank, or any name that is not a real *-verify agent) is
# self-attestation — the exact failure the architecture exists to prevent. These helpers make that
# impossible to ship SILENTLY: once a report exists it is a HARD gate, cleared only by routing the
# finding to its real reviewer or by an EXPLICIT, recorded operator-accept (mirrors the recall-audit
# REAL-MISS accept flow). Either way the message names which reviewer class is missing, so a roster
# hole gets backfilled rather than quietly repeated.
_SELF_REVIEW_MARKERS = ("orchestrator", "self", "operator", "executor", "author", "human", "none", "n/a")


def _verify_roster() -> set:
    """The set of REAL independent reviewer agents (`<executor>-verify`). Sourced from the actual
    agent definitions (`.claude/agents/*-verify.md`) UNIONed with the routing-map's executor agents
    (+ '-verify'), so neither a missing agent file nor a routing-only class under-counts and wrongly
    flags a legitimate reviewer. Lower-cased for case-insensitive matching."""
    roster = set()
    root = _repo_root()
    adir = root / ".claude" / "agents"
    if adir.is_dir():
        for p in adir.glob("*-verify.md"):
            roster.add(p.stem.lower())
    rm = root / "skills" / "_contract" / "routing-map.json"
    if rm.is_file():
        try:
            d = json.loads(rm.read_text(encoding="utf-8"))
            for c in d.get("categories", []):
                for a in (c.get("agents") or []):
                    roster.add(f"{str(a).lower()}-verify")
        except Exception:  # noqa: BLE001
            pass
    return roster


def _is_independent_reviewer(name: str, roster: set) -> bool:
    """True iff `name` is a real, independent `*-verify` reviewer — not the orchestrator/executor
    self-reviewing. A self/orchestrator marker disqualifies it regardless of roster; otherwise it
    must be a known roster member. With no resolvable roster (a stripped deployment) we fall back to
    the structural signal: a '<x>-verify' name carrying no self marker."""
    n = (name or "").strip().lower()
    if not n or any(m in n for m in _SELF_REVIEW_MARKERS):
        return False
    if roster:
        return n in roster
    return n.endswith("-verify")


def _review_of(f: dict, eng: Path) -> tuple:
    """(verdict, reviewer) for a finding, preferring the inline `review{}` block and falling back to
    `reviews/<id>.verdict.json` (root or per-skill). verdict defaults from `status` when neither
    carries one (verified→accepted, rejected→rejected)."""
    r = f.get("review") or {}
    verdict, reviewer = r.get("verdict"), r.get("reviewer")
    if not (verdict and reviewer):
        fid = f.get("id")
        if fid:
            cands = [eng / "reviews" / f"{fid}.verdict.json"] + sorted(eng.glob(f"*/reviews/{fid}.verdict.json"))
            for vp in cands:
                if vp.is_file():
                    try:
                        vd = json.loads(vp.read_text(encoding="utf-8")) or {}
                    except Exception:  # noqa: BLE001
                        continue
                    verdict = verdict or vd.get("verdict")
                    reviewer = reviewer or vd.get("reviewer")
                    if verdict and reviewer:
                        break
    if not verdict:
        st = f.get("status")
        verdict = "accepted" if st == "verified" else "rejected" if st == "rejected" else ""
    return verdict, (reviewer or "")


def _self_verified_accepts(eng: Path) -> dict:
    """Operator acknowledgments that a reportable finding may ship self-/orchestrator-verified because
    no independent `*-verify` reviewer class covers it. File: `<eng>/reviews/self_verified_accepts.json`,
    either `{"RS-...": "reason"}` or `[{"id":..., "reason":..., "by":...}]`. Returns id→reason for every
    entry with a non-empty reason (a blank reason is not an accept)."""
    p = eng / "reviews" / "self_verified_accepts.json"
    if not p.is_file():
        return {}
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}
    out = {}
    if isinstance(d, dict):
        for k, v in d.items():
            reason = v if isinstance(v, str) else (v.get("reason") if isinstance(v, dict) else "")
            if isinstance(reason, str) and reason.strip():
                out[str(k)] = reason.strip()
    elif isinstance(d, list):
        for e in d:
            if isinstance(e, dict) and e.get("id") and str(e.get("reason", "")).strip():
                out[str(e["id"])] = str(e["reason"]).strip()
    return out


def _independent_review_check(eng: Path, findings: list) -> tuple:
    """(hard_errors, warnings) for the independent-review gate. Only findings that actually reach
    reporting (effective verdict accepted/blocked) are in scope. A report present makes an
    un-reviewed, un-accepted finding a HARD error; before a report it is a soft warning."""
    roster = _verify_roster()
    accepts = _self_verified_accepts(eng)
    report = _report_present(eng)
    flagged, accepted = [], []
    for f in findings:
        if not isinstance(f, dict):
            continue
        verdict, reviewer = _review_of(f, eng)
        if verdict not in ("accepted", "blocked"):
            continue  # not reportable → the gate doesn't apply
        if _is_independent_reviewer(reviewer, roster):
            continue
        fid = f.get("id", "<no-id>")
        cat = f.get("category") or {}
        hint = cat.get("owasp") or cat.get("cwe") or cat.get("wstg") or "uncategorized"
        who = reviewer or "(none)"
        (accepted if fid in accepts else flagged).append((fid, hint, who))
    hard, warns = [], []
    for fid, hint, who in flagged:
        msg = (f"{fid} [{hint}] reviewed by '{who}', not an independent *-verify agent — "
               f"self/orchestrator-attested. Route it to the matching <class>-verify reviewer, or record "
               f"an operator-accept in reviews/self_verified_accepts.json (\"{fid}\": \"why no reviewer covers this class\")")
        if report:
            hard.append("independent-review gate (report present → every reportable finding needs an "
                        f"independent *-verify reviewer): {msg}")
        else:
            warns.append(msg + " [becomes a hard gate once a report exists]")
    for fid, hint, who in accepted:
        warns.append(f"self-verification operator-accepted: {fid} [{hint}] by '{who}' — "
                     f"{accepts[fid]} (backfill a {hint} *-verify reviewer to remove this exception)")
    return hard, warns


def validate_engagement(eng: Path, as_json: bool) -> bool:
    cvss_mod = _try_import_cvss()
    scope_text = _scope_text(eng)
    top_warnings = []
    if not scope_text:
        top_warnings.append("scope.yaml absent — scope compliance cannot be auto-checked (flagged, not failed)")
    # Transport-blocked AUTO-POPULATE (reliability): BEFORE the coverage checks read the ledger, flip any
    # web category still pending / attempted-empty to `blocked` when the latest diagnostics run shows a
    # WAF-blocked host — so a clean clear on a blocked host is attributed to the transport block, not read
    # as a silent gap or a trustworthy clear. Sourced from transport health, not from the model noticing.
    flipped_cov = _auto_populate_blocked_coverage(eng)
    if flipped_cov:
        shown = ", ".join(str(x) for x in flipped_cov[:6]) + ("…" if len(flipped_cov) > 6 else "")
        top_warnings.append(f"transport-blocked: auto-marked {len(flipped_cov)} web coverage categor"
                            f"{'y' if len(flipped_cov) == 1 else 'ies'} 'blocked' from diagnostics transport "
                            f"health ({shown}) — a clear on a WAF-blocked host, attributed to the block (not clean)")
    # Coverage: soft while hunting, HARD once a report exists (fix #2 — no report over silent gaps).
    coverage_errors = _coverage_hard_errors(eng)
    if not coverage_errors:
        top_warnings.extend(_coverage_warnings(eng))
    # Surface coverage (fix #5): HARD once a report + a surface ledger both exist; else a soft nudge.
    coverage_errors += _surface_hard_errors(eng)
    top_warnings.extend(_surface_warnings(eng))
    # Re-convergence (fix #6): HARD once a report + a non-empty inbox exist — no report over un-routed
    # mid-hunt discoveries (the single-pass leak).
    coverage_errors += _reconverge_hard_errors(eng)
    # Coordination-artifact integrity: HARD once a report exists — the inbox / surface ledger / coverage
    # ledger must obey their OWN vocabularies (no folded-in out-of-vocab signal or out-of-enum kind).
    integrity_errors = _coordination_integrity_errors(eng)
    # Recall audit (false-negative altitude): HARD once a report exists — a shallow-clear /
    # skipped-but-signalled / never-run gap must be closed or explicitly accepted (fix: the recall audit
    # was advisory only, so a report shipped over ~10 HIGH shallow-clear gaps).
    recall_errors, recall_warns = _recall_check(eng)
    top_warnings.extend(recall_warns)
    # Attack-chain integrity: HARD once a report exists — every chain step resolves to an accepted/blocked
    # finding and every chain finding is composite (fix: there was no attack-chain validator).
    chain_errors = _chain_hard_errors(eng)
    if not any(eng.rglob("host_discovery.json")):
        top_warnings.append("no host_discovery.json — recon's structured host/port map wasn't persisted; "
                            "the console's Ports view will be empty (Assets falls back to scope+findings). "
                            "Run host-discovery / emit <eng>/host-discovery/host_discovery.json.")
    # Notebook (leads + recon intel + evidence + RoE + accounts): SOFT always — makes a zero-finding hunt
    # legible; encouraged, never a hard gate (keeps engagements predating the notebook passing).
    top_warnings.extend(_notebook_warnings(eng))

    findings, source = _discover_engagement_findings(eng)
    if findings is None:
        print(json.dumps({"engagement": str(eng), "pass": False, "error": source}) if as_json else f"[!] {source}")
        return False
    if not as_json:
        top_warnings.append(f"findings source: {source} ({len(findings)} finding(s))")

    verdict_ids = _collect_verdict_ids(eng)

    # Independent-review gate (#1): no report over self-/orchestrator-attested findings. HARD once a
    # report exists; a soft warning while hunting. Cleared by a real *-verify reviewer or a recorded
    # operator-accept (reviews/self_verified_accepts.json).
    review_errors, review_warns = _independent_review_check(eng, findings)
    top_warnings.extend(review_warns)

    # Duplicate finding-id gate: HARD once a report exists (ids must be engagement-unique); silent before.
    dup_errors = _duplicate_id_errors(eng, findings)

    # Diagnostics gate (reliability): HARD once a report exists AND it has zero reportable findings — the
    # empty report must carry an EXPLAINED diagnostics outcome (clean-tested, or degraded-empty/failed with
    # a reason). An unexplained empty is a silent "we produced nothing", not a clean result (empty ≠ clean).
    diagnostics_errors = _diagnostics_hard_errors(eng, findings)

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
    gate_ok = ((not failed) and (not coverage_errors) and (not review_errors)
               and (not dup_errors) and (not integrity_errors) and (not recall_errors)
               and (not chain_errors) and (not diagnostics_errors))

    if as_json:
        print(json.dumps({"engagement": str(eng), "pass": gate_ok,
                          "findings_checked": len(results), "failed": len(failed),
                          "coverage_errors": coverage_errors,
                          "review_errors": review_errors,
                          "duplicate_id_errors": dup_errors,
                          "integrity_errors": integrity_errors,
                          "recall_errors": recall_errors,
                          "chain_errors": chain_errors,
                          "diagnostics_errors": diagnostics_errors,
                          "results": results, "warnings": all_warnings,
                          "unreferenced_evidence": orphans, "cvss_available": bool(cvss_mod)}, indent=2))
    else:
        print(f"# Engagement review -- {eng}")
        for r in results:
            box = "x" if r["passed"] else " "
            print(f"- [{box}] {r['id']}  [{r['severity']}/{r['status']}]  -- {r['detail']}")
        if coverage_errors:
            print("\n✗ coverage gate FAILED (a report is present, so the ledger must be complete):")
            for ce in coverage_errors:
                print(f"  - {ce}")
        if review_errors:
            print("\n✗ independent-review gate FAILED (a finding reached reporting without an independent reviewer):")
            for re_ in review_errors:
                print(f"  - {re_}")
        if dup_errors:
            print("\n✗ duplicate finding-id gate FAILED (a report is present, so ids must be engagement-unique):")
            for de in dup_errors:
                print(f"  - {de}")
        if integrity_errors:
            print("\n✗ coordination-integrity gate FAILED (a coordination artifact broke its own vocabulary):")
            for ie in integrity_errors:
                print(f"  - {ie}")
        if recall_errors:
            print("\n✗ recall-audit gate FAILED (a report is present, so no un-closed shallow-clear/"
                  "skipped-but-signalled/never-run gap):")
            for rce in recall_errors:
                print(f"  - {rce}")
        if chain_errors:
            print("\n✗ attack-chain gate FAILED (a chain step is unresolved/non-reportable, or a chain "
                  "finding is not composite):")
            for che in chain_errors:
                print(f"  - {che}")
        if diagnostics_errors:
            print("\n✗ diagnostics gate FAILED (a zero-finding report must carry an explained diagnostics "
                  "outcome — empty ≠ clean):")
            for dge in diagnostics_errors:
                print(f"  - {dge}")
        if all_warnings:
            print("\n⚠ warnings (non-failing):")
            for w in all_warnings:
                print(f"  - {w}")
        if orphans:
            print(f"\nℹ {len(orphans)} non-empty evidence file(s) not referenced by any finding "
                  f"(e.g. {orphans[0]})")
        if not cvss_mod:
            print("\nℹ scripts/cvss.py not importable — CVSS/severity drift check skipped")
        verdict = "PASS" if gate_ok else "FAIL"
        print(f"\n{verdict}: {len(results) - len(failed)}/{len(results)} finding(s) pass hard checks; "
              f"{len(failed)} failure(s), {len(coverage_errors)} coverage-gate error(s), "
              f"{len(review_errors)} independent-review error(s), {len(dup_errors)} duplicate-id error(s), "
              f"{len(integrity_errors)} coordination-integrity error(s), {len(recall_errors)} recall-audit "
              f"error(s), {len(chain_errors)} attack-chain error(s), {len(diagnostics_errors)} diagnostics "
              f"error(s), {len(all_warnings)} warning(s).")
        if failed:
            print("A failed finding is missing a required field or cites missing/empty evidence => fix before reporting.")
        if coverage_errors:
            print("A report is present but routed categories are unaccounted for => run every pending category, "
                  "or record an explicit skip reason, before reporting.")
        if review_errors:
            print("A reportable finding was self-/orchestrator-verified => route it to its independent <class>-verify "
                  "reviewer, or record an explicit operator-accept in reviews/self_verified_accepts.json before reporting.")
        if dup_errors:
            print("Two findings share an id => give each a unique RS-YYYY-NNN before reporting.")
        if integrity_errors:
            print("A coordination artifact (inbox / surface ledger / coverage ledger) holds an out-of-vocab "
                  "signal or out-of-enum surface kind => quarantine it (reconverge --apply) and re-plan, "
                  "don't fold an invalid token into the ledgers.")
        if recall_errors:
            print("A clean-looking class ran shallow (signalled surface, ladder unexhausted) or a routed "
                  "class never ran => escalate + re-run it, or record an explicit, reasoned accept in "
                  "reviews/recall_audit_accepts.json before reporting.")
        if chain_errors:
            print("An attack chain references a non-accepted/unknown finding, or a chain finding isn't "
                  "composite:true => fix the chain's step ids / set composite:true before reporting.")
        if diagnostics_errors:
            print("A zero-finding report can't prove it was a real clean test => emit runtime/diagnostics.json "
                  "whose latest run outcome is 'clean-tested', or 'degraded-empty'/'failed' with a "
                  "degraded_reason, before reporting (empty ≠ clean).")
    return gate_ok


def main() -> None:
    # A real run may land on a console/pipe using a legacy codepage (Windows cp1252) that can't encode
    # the status glyphs this gate prints (⚠/✗/ℹ); make stdout UTF-8 so it never dies on a UnicodeEncodeError.
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:  # noqa: BLE001 — older/replaced streams may lack reconfigure; printing stays best-effort
        pass
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
