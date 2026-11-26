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


def _try_import_vrt():
    """Import scripts/vrt.py (the deterministic VRT resolver) by path. None when unavailable —
    the VRT governance gate then no-ops rather than crashing an engagement."""
    try:
        sys.path.insert(0, str(_repo_root() / "scripts"))
        import vrt  # type: ignore
        return vrt
    except Exception:
        return None


def _scope_text(eng: Path) -> str:
    sp = eng / "scope.yaml"
    return sp.read_text(encoding="utf-8", errors="replace") if sp.is_file() else ""


def _scope_program(eng: Path) -> dict:
    """Parse the OPTIONAL `program:` block from scope.yaml into {platform, taxonomy, name}.
    Absent / platform:none => an ordinary pentest (the VRT gate no-ops). Stdlib-only: reads
    the direct keys of the top-level `program:` mapping (mirrors validate.py's block parser)."""
    txt = _scope_text(eng)
    out = {}
    in_block = False
    indent = None
    for ln in txt.splitlines():
        if re.match(r"^program\s*:\s*(#.*)?$", ln):
            in_block = True
            continue
        if not in_block:
            continue
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        if not ln.startswith((" ", "\t")):
            break  # a non-indented line ends the block
        m = re.match(r"^(\s+)([A-Za-z0-9_]+)\s*:\s*(.*)$", ln)
        if not m:
            continue
        sp, k, v = m.groups()
        if indent is None:
            indent = len(sp)
        if len(sp) != indent:
            continue  # only the block's own direct keys
        v = v.split("#", 1)[0].strip().strip('"').strip("'")
        out[k] = v
    return out


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


def _try_import_model_ledger():
    # import scripts/model_ledger.py by PATH so nothing on sys.path can shadow it (mirrors _try_import_coverage)
    try:
        import importlib.util
        p = _repo_root() / "scripts" / "model_ledger.py"
        if not p.is_file():
            return None
        spec = importlib.util.spec_from_file_location("rs_model_ledger", p)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


def _report_present(eng: Path) -> bool:
    """A consolidated report means the engagement is claiming DONE (reporting ran)."""
    return (eng / "report" / "findings_consolidated.json").is_file()


# --- gate-arming: fire the completeness gates at CLOSE, not only on report-presence ---------------- #
# "A gate the real workflow routes around is not a gate." The hard completeness gates used to arm ONLY
# when `report/findings_consolidated.json` existed. When the autorun pipeline crashed and a hunter swarm
# wrote findings.json / report.md DIRECTLY (the shopware-2026-11-19 failure), the report file was never
# produced, every hard gate early-returned [], and a 175-surface-untested / all-pending-coverage audit
# passed the gate and was narrated "hardened". The gates now ALSO arm on run-COMPLETION: executor findings
# exist AND the run is terminal (a concluded runtime/diagnostics.json run) — so they fire at audit close
# even when reporting was skipped. Report-present stays an arming trigger (reporting ran = DONE), just not
# the only one.

# The outcomes diagnostics.py ever writes — each means a run leg CONCLUDED (diagnostics is written only
# after a post-run gate), so a latest run carrying one of these is a terminal (closed) run.
_TERMINAL_DIAG_OUTCOMES = {"produced-findings", "clean-tested", "degraded-empty", "failed"}


def _run_is_terminal(eng: Path) -> bool:
    """True when the engagement's latest runtime/diagnostics.json run CONCLUDED (a recognized terminal
    outcome). A terminal run means the engine leg ended — the audit is AT CLOSE even if reporting was
    skipped/crashed. A mid-hunt engagement with no concluded run (no diagnostics) is NOT terminal."""
    run = _latest_run(_load_diagnostics(eng))
    return bool(run) and run.get("outcome") in _TERMINAL_DIAG_OUTCOMES


def _gates_armed(eng: Path, findings=None) -> bool:
    """Gate-arming predicate — the completeness gates fire when the engagement is at CLOSE by EITHER
    signal: a consolidated report exists (reporting ran), OR executor findings exist AND the run is
    terminal (a concluded diagnostics run). The second arms the gates even when reporting is skipped or
    crashed and a hunter swarm wrote findings.json directly. For a ZERO-finding engagement this collapses
    to exactly `_report_present` (no findings → the findings-trigger can't fire), so the only behavior that
    CHANGES is a with-findings, concluded-run engagement — which is precisely where the gates must fire."""
    if _report_present(eng):
        return True
    if findings is None:
        findings, _ = _discover_engagement_findings(eng)
    return bool(findings) and _run_is_terminal(eng)


def _scope_is_source(eng: Path) -> bool:
    """True when this engagement was granted SOURCE access (white-box), i.e. scope carries a `source:`
    block. Best-effort + stdlib-only: prefers the generated runtime/scope.json (`source_repo`, written by
    scope.build_projection), and falls back to detecting a top-level `source:` mapping in scope.yaml so a
    hand-authored engagement with no runtime projection is still recognized. `scope.source` is the signal
    that gates the WHITE-BOX requirements (app_model required, a populated code-audit surface slice,
    candidate→finding reconciliation) — so a black-box engagement never trips them."""
    sj = eng / "runtime" / "scope.json"
    if sj.is_file():
        try:
            d = json.loads(sj.read_text(encoding="utf-8"))
            if isinstance(d, dict) and isinstance(d.get("source_repo"), dict) and d["source_repo"]:
                return True
        except Exception:  # noqa: BLE001 — a half-written projection must never crash the gate
            pass
    txt = _scope_text(eng)
    # a `source:` key at column 0 whose block carries a repo_url/local_path/commit/branch sub-key
    if re.search(r"(?m)^source:\s*$", txt) and re.search(r"(?m)^\s+(repo_url|local_path|commit|branch):", txt):
        return True
    return False


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
    """HARD diagnostics gate (reliability) — active once a report exists. Two cases:

    * report WITH reportable findings — the latest diagnostics run must not CONTRADICT it. The only
      diagnostics writer is the launcher's post-run gate, so an engagement driven through the interactive
      Skill path keeps a stale CLI-init / blocked-on-approval `runs[-1]` (outcome `degraded-empty`,
      `findings_count` 0) → a false "Assessment degraded" even over accepted findings. If a run exists and
      its outcome/findings_count contradict the report, HARD-fail with the `scripts/close.py` remedy. A
      report WITH findings and NO diagnostics file stays a non-error (close.py is advised, never required
      here — nothing stale to contradict).
    * zero-finding report — the empty must PROVE it was a real clean test, not a silent 'we were blocked /
      produced nothing'. The latest run must carry an EXPLAINED outcome: `clean-tested`, or
      `degraded-empty`/`failed` WITH a `degraded_reason`. A missing diagnostics file, a missing/contradictory
      outcome, or an unexplained empty HARD-fails (empty ≠ clean).

    Reads only the stable run-record fields (`outcome`, `findings_count`, `degraded_reason`). [] until the
    gates arm (a report exists, or executor findings + a terminal run)."""
    if not _gates_armed(eng, findings):
        return []
    rc = _reportable_findings_count(eng, findings)
    if rc > 0:
        run = _latest_run(_load_diagnostics(eng))
        if run is None:
            return []  # no diagnostics recorded → nothing stale to contradict (close.py advised, not required)
        outcome = run.get("outcome")
        try:
            fc = int(run.get("findings_count") or 0)
        except (TypeError, ValueError):
            fc = 0
        if outcome != "produced-findings" or fc == 0:
            return [("diagnostics gate (report has findings → the latest runtime/diagnostics.json run must "
                     "agree): latest runtime/diagnostics.json run is stale / contradicts the report "
                     f"(outcome={outcome!r}, findings_count={fc}, but the report carries {rc} reportable "
                     "finding(s)) — run `python scripts/close.py --engagement <dir>` to record this "
                     "engagement's outcome.")]
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

    Returns [] until the gates arm (hunting phase) or coverage can't be checked (surfaced
    elsewhere — don't fabricate a failure)."""
    if not _gates_armed(eng):
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
    """HARD surface gate (fix #5, strict since fix: universal emission) — active once the gates arm.

    A closed audit must not ship with surface recon discovered but no executor tested (the leak category
    coverage can't see). Now that the recon feeders emit the ledger universally and `surface.py --plan`
    is idempotent, a MISSING ledger at close is itself a FAIL (not a warning) — it means surface
    coverage was never tracked, the juice-shop-2026-10-20 blind spot. A PRESENT ledger is validated
    STRICT, so an empty-but-present ledger (feeders didn't populate it) also fails.

    For a `scope.source` (white-box) engagement the strict check is SCOPED to the `routed_to:code-audit`
    slice: the code-audit executor is the one consumer that must prove it closed the whole SOURCE surface
    (entry points / source-audit leads / high-risk files / state-ops / authz-routes), independently of a
    sibling's still-pending black-box recon surface in the same shared ledger. Scoping + strict also means
    the gate CANNOT pass vacuously on zero code-audit surfaces — an empty slice fails, so a ledger holding
    only black-box kinds is a recall gap, not a pass. Mirrors `_coverage_hard_errors`."""
    if not _gates_armed(eng):
        return []
    if not (eng / "surface_ledger.json").is_file():
        return ["surface gate (close → a surface ledger is required): no surface_ledger.json — "
                "surface coverage was never tracked (run scripts/surface.py --plan --engagement <dir> "
                "after recon; it is idempotent and safe to re-run)"]
    sf = _try_import_surface()
    if not sf:
        return []
    source = _scope_is_source(eng)
    routed_to = "code-audit" if source else None
    try:
        led = json.loads((eng / "surface_ledger.json").read_text(encoding="utf-8"))
        ok, _lines, msgs = sf.validate(led, strict=True, routed_to=routed_to)
    except Exception:  # noqa: BLE001
        return []
    if ok:
        return []
    tag = ("surface gate (scope.source → the code-audit source surface must be tested/accounted)" if source
           else "surface gate (close → surface must be tested/accounted)")
    return [f"{tag}: {m}" for m in msgs]


def _surface_warnings(eng: Path) -> list:
    """Soft nudge DURING the hunt (gates not yet armed): emit the surface ledger after recon so the
    close-time strict gate has something to check."""
    if not _gates_armed(eng) and not (eng / "surface_ledger.json").is_file():
        return ["no surface_ledger.json yet — emit it after recon (scripts/surface.py --plan "
                "--engagement <dir>); it becomes a hard gate at close"]
    return []


def _code_audit_surface_count(eng: Path) -> int:
    """How many ledger surfaces are routed to the code-audit consumer (the white-box source slice).
    0 means the source surface was never enumerated (the ledger holds only black-box recon kinds)."""
    sl = eng / "surface_ledger.json"
    if not sl.is_file():
        return 0
    try:
        led = json.loads(sl.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return 0
    return sum(1 for s in (led.get("surfaces") or [])
               if isinstance(s, dict) and "code-audit" in (s.get("routed_to") or []))


def _whitebox_shape_errors(eng: Path) -> list:
    """HARD white-box-shape gate (fix #3) — active only for a `scope.source` engagement once the gates
    arm. A source-granted audit MUST have produced the white-box model and enumerated the source surface,
    or it isn't a white-box audit at all — it is a black-box recon run wearing a source grant:

      * `code-audit/app_model.json` (the required white-box model artifact) must exist; AND
      * the surface ledger must carry >=1 `routed_to:code-audit` surface.

    A ledger holding only black-box kinds (endpoint/form/sink, all discovered_by content-discovery) with
    ZERO code-audit-routed surfaces is a RECALL GAP — the white-box pipeline never modeled the app or
    enumerated its source surface (the shopware-2026-11-19 failure: 175 black-box surfaces, 0 code-audit,
    no app_model) — not a pass. [] for a black-box engagement or before the gates arm."""
    if not _scope_is_source(eng):
        return []
    if not _gates_armed(eng):
        return []
    errs = []
    if not (eng / "code-audit" / "app_model.json").is_file():
        errs.append("white-box gate (scope.source → the app model is required): no code-audit/app_model.json "
                    "— the required white-box model artifact was never written. Model the app (entry points / "
                    "state-ops / authz-routes / high-risk files) first; scripts/surface.py --plan seeds the "
                    "code-audit surface slice from it.")
    if _code_audit_surface_count(eng) == 0:
        errs.append("white-box gate (scope.source → the source surface must be enumerated + routed): the "
                    "surface ledger has ZERO routed_to:code-audit surfaces — it holds only black-box recon "
                    "surface, so the white-box source surface (entry points / source-audit leads / high-risk "
                    "files / state-ops / authz-routes) was never enumerated. Run scripts/surface.py --plan "
                    "after the source-audit + app_model so the code-audit slice is populated.")
    return errs


def _source_candidate_ids(eng: Path) -> list:
    """The source-audit candidate ids (sa-*) from source-audit/source_context.json — the sink/lead
    candidates a white-box audit must each reconcile (confirm/refute as a finding, or test/skip as a
    source-lead surface). [] when there is no source_context.json."""
    sc = eng / "source-audit" / "source_context.json"
    if not sc.is_file():
        return []
    try:
        d = json.loads(sc.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return []
    out = []
    for c in (d.get("candidates") or []):
        if isinstance(c, dict) and c.get("id"):
            out.append(str(c["id"]))
    return out


def _reconciled_candidate_ids(eng: Path, findings: list) -> set:
    """Candidate ids that ARE accounted for: referenced by a finding's `candidate_refs`, OR carried by a
    `source-lead` surface marked tested/skipped (the surface value begins with the candidate id, e.g.
    'sa-001 sqli @ db.py:20')."""
    reconciled = set()
    for f in (findings or []):
        if isinstance(f, dict):
            for r in (f.get("candidate_refs") or []):
                reconciled.add(str(r))
    sl = eng / "surface_ledger.json"
    if sl.is_file():
        try:
            led = json.loads(sl.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            led = {}
        for s in (led.get("surfaces") or []):
            if not isinstance(s, dict) or s.get("kind") != "source-lead":
                continue
            if str(s.get("status")) not in ("tested", "skipped"):
                continue
            tok = str(s.get("value") or "").split(" ", 1)[0]  # "sa-001 sqli @ ..." -> "sa-001"
            if tok:
                reconciled.add(tok)
    return reconciled


def _candidate_reconciliation_errors(eng: Path, findings: list) -> list:
    """HARD candidate→finding reconciliation gate (fix #6) — `scope.source` engagements, once armed.

    Every source_context candidate id must be RECONCILED: either referenced by a finding's `candidate_refs`
    (the lead became a confirmed/refuted finding), OR carried as a `source-lead` surface marked tested or
    skipped (accounted for in the ledger). An unreconciled candidate is a recall gap — a dangerous-sink
    lead the white-box audit neither turned into a finding nor explicitly accounted for. [] for a black-box
    engagement, before the gates arm, or when there is no source_context."""
    if not _scope_is_source(eng):
        return []
    if not _gates_armed(eng, findings):
        return []
    cand_ids = _source_candidate_ids(eng)
    if not cand_ids:
        return []
    reconciled = _reconciled_candidate_ids(eng, findings)
    unreconciled = [cid for cid in cand_ids if cid not in reconciled]
    if not unreconciled:
        return []
    shown = ", ".join(unreconciled[:12]) + ("…" if len(unreconciled) > 12 else "")
    return [f"candidate-reconciliation gate (scope.source → every source_context candidate must become a "
            f"finding or be accounted for): {len(unreconciled)}/{len(cand_ids)} candidate(s) unreconciled "
            f"({shown}) — cite each in a finding's candidate_refs, or mark its source-lead surface "
            f"tested/skipped (with a reason) in the surface ledger."]


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
    if not _gates_armed(eng):
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

    Returns [] until the gates arm, or when the vocab/enum can't be read (surfaced elsewhere)."""
    if not _gates_armed(eng):
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
_RECALL_GATED_TYPES = {"shallow-clear", "skipped-but-signalled", "pending-at-close", "never-run", "blocked-unverified"}


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
    if not _gates_armed(eng):
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
    if not _gates_armed(eng):
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

    Returns one error per duplicated id (with its occurrence count); [] until the gates arm."""
    if not _gates_armed(eng, findings):
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
        item = item or {}
        # code_citation = inline VERBATIM source bytes (white-box evidence); its vault `ref` is OPTIONAL —
        # the proof is file/line/snippet. A vault `ref`, when present, is still validated as a real file.
        if item.get("type") == "code_citation":
            miss = [k for k in ("file", "line", "snippet")
                    if item.get(k) in (None, "") or str(item.get(k)).strip() == ""]
            if miss:
                return False, f"evidence #{i} code_citation missing verbatim source bytes ({', '.join(miss)})", warns
            ref = item.get("ref")
            if ref:
                p = eng / ref
                if not p.is_file():
                    return False, f"evidence #{i} code_citation ref not found: {ref}", warns
                if p.stat().st_size == 0:
                    return False, f"evidence #{i} code_citation ref is 0 bytes: {ref}", warns
            continue
        ref = item.get("ref")
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
    # CVSS DRIFT (declared severity != recomputed rating, no potential_severity) is gated at engagement
    # altitude by _cvss_drift_check (R7): a soft warning while hunting, a HARD fail once a report exists
    # (same escalation shape as the self-attestation gate). Here we only surface an UNSCORABLE vector as a
    # per-finding hygiene warning.
    if cvss_mod and f.get("cvss_vector"):
        try:
            cvss_mod.score_vector(f["cvss_vector"])
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
    report = _gates_armed(eng, findings)
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


# --- CVSS-drift HARD gate (R7) ------------------------------------------------------------------- #
# The gate recomputes each finding's CVSS vector (scripts/cvss.py). A declared `severity` that differs
# from the recomputed rating, with NO `potential_severity` set, is DRIFT — the severity the report would
# print is not what the vector proves. This USED to only warn; now it follows the self-attestation
# escalation shape: a soft warning while hunting, a HARD fail once a report exists (a report must not
# ship a finding whose severity contradicts its own CVSS vector and isn't flagged demonstrated-vs-
# potential). A finding carrying `potential_severity` is a legitimate demonstrated-vs-potential gap and
# is never drift.
def _cvss_drift_check(eng: Path, findings: list, cvss_mod) -> tuple:
    """(hard_errors, warnings) for the CVSS-drift gate (R7). [] / [] when cvss.py is unavailable."""
    if not cvss_mod:
        return [], []
    armed = _gates_armed(eng, findings)
    hard, warns = [], []
    for f in findings:
        if not isinstance(f, dict) or not f.get("cvss_vector") or f.get("potential_severity"):
            continue
        try:
            score, rating, _ = cvss_mod.score_vector(f["cvss_vector"])
        except Exception:  # noqa: BLE001 — the per-finding 'not scorable' warning already surfaces this
            continue
        declared = str(f.get("severity", "")).lower()
        if rating.lower() == declared:
            continue
        fid = f.get("id", "<no-id>")
        msg = (f"{fid}: declared severity '{declared}' != recomputed CVSS rating '{rating.lower()}' "
               f"({score}) with no potential_severity set — fix the vector/severity (do not hand-override "
               f"the score), or set potential_severity (demonstrated-vs-potential)")
        if armed:
            hard.append("cvss-drift gate (report present → a finding's severity must match its recomputed "
                        f"CVSS rating or be flagged demonstrated-vs-potential): {msg}")
        else:
            warns.append(msg + " [becomes a hard gate once a report exists]")
    return hard, warns


# --- VRT-governance HARD gate (L-B) ------------------------------------------------------------- #
# A FABRICATED VRT category once shipped in a bug-bounty submission (an operator caught it). On a
# program-flagged bug-bounty engagement — scope.yaml program.platform != none AND program.taxonomy ==
# vrt — every ACCEPTED, in-scope, reportable finding MUST carry a structured `vrt{}` block whose `path`
# RESOLVES in the pinned taxonomy (scripts/vrt.py path_exists) and whose priority passes
# elevation_errors (anti-fabrication + anti-inflation). Same escalation shape as the cvss-drift gate: a
# soft warning while hunting, a HARD fail once a report exists / the run is terminal. A NON-program
# engagement (program.platform none / absent, or taxonomy != vrt) is COMPLETELY unaffected — the gate
# no-ops, so an ordinary pentest is byte-identical to before. Composite/kill-chain findings are skipped
# (they re-state component findings, which each carry their own VRT).
def _vrt_governance_check(eng: Path, findings: list, vrt_mod) -> tuple:
    """(hard_errors, warnings) for the VRT-governance gate. ([],[]) when the engagement is not a
    VRT-governed bug-bounty program."""
    prog = _scope_program(eng)
    platform = (prog.get("platform") or "none").strip().lower()
    taxonomy = (prog.get("taxonomy") or "none").strip().lower()
    if platform in ("", "none") or taxonomy != "vrt":
        return [], []  # not a VRT-governed bug-bounty engagement -> no-op (ordinary pentest)
    if not vrt_mod:
        return [], ["VRT governance: scripts/vrt.py not importable — a bug-bounty finding's VRT "
                    "path/priority could not be validated (restore scripts/vrt.py)"]
    armed = _gates_armed(eng, findings)
    scope_text = _scope_text(eng)
    hard, warns = [], []
    for f in findings:
        if not isinstance(f, dict):
            continue
        verdict, _ = _review_of(f, eng)
        if verdict not in ("accepted", "blocked"):
            continue  # only reportable findings are in scope for the gate
        if f.get("composite"):
            continue  # a composite re-states component findings; those carry the VRT
        # in-scope filter: an out-of-scope asset would be dropped by verify check #6 anyway
        if scope_text:
            host = _asset_host(f.get("asset", ""))
            root = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
            if host and host not in scope_text and root not in scope_text:
                continue
        fid = f.get("id", "<no-id>")
        vrt = f.get("vrt")
        if not isinstance(vrt, dict) or not vrt:
            msg = (f"{fid}: bug-bounty finding (program.taxonomy=vrt) carries NO `vrt{{}}` block — stamp "
                   f"its Vulnerability Rating Taxonomy path + priority (resolve it with "
                   f"`python scripts/vrt.py --resolve --cwe <CWE> / --category <class>`); a submission "
                   f"must not go out without a VRT")
        else:
            path = vrt.get("path")
            problems = []
            if not (isinstance(path, str) and vrt_mod.path_exists(path)):
                problems.append(f"vrt.path {path!r} does NOT resolve in the pinned taxonomy "
                                f"(fabricated VRT category)")
            else:
                problems += vrt_mod.elevation_errors(path, vrt.get("priority"),
                                                     vrt.get("priority_basis"),
                                                     vrt.get("priority_rationale"))
            if not problems:
                continue
            msg = f"{fid}: " + "; ".join(problems)
        if armed:
            hard.append("VRT-governance gate (report present → every accepted in-scope bug-bounty "
                        f"finding needs a valid, non-inflated VRT): {msg}")
        else:
            warns.append(msg + " [becomes a hard gate once a report exists]")
    return hard, warns


# --- Independent-reproducible-evidence HARD gate (R1) -------------------------------------------- #
# Today the per-finding gate only checks an evidence ref exists + is non-zero, so a confirmed/Medium+
# finding passes with its ONLY evidence being the executor's own analysis/log/tool_output (circular
# evidence — the thing that produced the finding is not proof of the finding; the shopware run did this
# 48/48). This gate adds a severity×confidence rule: a `confirmed` OR Medium+ REPORTABLE finding must
# carry >=1 INDEPENDENT artifact. Independent = a reproducible artifact a reviewer can re-check:
# request_response | poc_script | screenshot | dom_capture, or the white-box code_citation (verbatim
# source bytes at file:line). Evidence that is ONLY log/tool_output inside the producing skill's own dir
# is circular and caps confidence at `probable` (cannot read `confirmed`). Same escalation shape as the
# self-attestation gate: warn while hunting, HARD once a report exists. Only reportable findings
# (verdict accepted/blocked) are in scope — a rejected/needs-evidence finding never reaches a report.
_INDEPENDENT_EVIDENCE_TYPES = {"request_response", "poc_script", "screenshot", "dom_capture", "code_citation"}
_WEAK_EVIDENCE_TYPES = {"log", "tool_output"}
_MEDIUM_PLUS_SEVERITIES = {"critical", "high", "medium"}


def _independent_evidence_check(eng: Path, findings: list) -> tuple:
    """(hard_errors, warnings) for the independent-reproducible-evidence gate (R1)."""
    armed = _gates_armed(eng, findings)
    hard, warns = [], []
    for f in findings:
        if not isinstance(f, dict):
            continue
        verdict, _ = _review_of(f, eng)
        if verdict not in ("accepted", "blocked"):
            continue  # not reportable → the gate doesn't apply
        conf = str(f.get("confidence", "")).lower()
        sev = str(f.get("severity", "")).lower()
        if conf != "confirmed" and sev not in _MEDIUM_PLUS_SEVERITIES:
            continue
        ev = [it for it in (f.get("evidence") or []) if isinstance(it, dict)]
        if any(it.get("type") in _INDEPENDENT_EVIDENCE_TYPES for it in ev):
            continue  # has at least one independent artifact → ok
        fid = f.get("id", "<no-id>")
        # circular-evidence detail: ALL evidence is log/tool_output inside the producing skill's own dir
        src = f.get("_rs_source_skill")
        weak_only = bool(ev) and all(it.get("type") in _WEAK_EVIDENCE_TYPES for it in ev)
        own_dir = bool(src) and all(
            str(it.get("ref", "")).replace("\\", "/").startswith(f"{src}/") for it in ev)
        if conf == "confirmed" and weak_only and own_dir:
            msg = (f"{fid} [{sev}/confirmed] cites ONLY log/tool_output inside its own producing dir "
                   f"'{src}/' (circular evidence) — that caps confidence at 'probable'. A 'confirmed' "
                   f"reading needs an INDEPENDENT artifact: request_response / poc_script / screenshot / "
                   f"dom_capture / code_citation")
        else:
            why = "confirmed" if conf == "confirmed" else f"{sev}-severity"
            msg = (f"{fid} [{sev}/{conf or 'n/a'}] is {why} but cites no INDEPENDENT artifact "
                   f"(request_response / poc_script / screenshot / dom_capture / code_citation) — its "
                   f"evidence is only log/tool_output/analysis (circular). Add a reproducible artifact, "
                   f"or lower severity/confidence to match what the evidence proves")
        if armed:
            hard.append("independent-evidence gate (report present → a confirmed/Medium+ finding needs a "
                        f"reproducible independent artifact): {msg}")
        else:
            warns.append(msg + " [becomes a hard gate once a report exists]")
    return hard, warns


# --- Cross-model second-verification HARD gate (R3) --------------------------------------------- #
# Every `*-verify` agent runs `model: inherit` (the executor's model), so a shared-model hallucination
# can pass BOTH the executor and its reviewer. The model-pinned `adversarial-verify` agent re-runs the
# base checks on a DIFFERENT model and records a `secondary_review`. This gate requires that second
# verdict for the high-cost-to-be-wrong findings — an `accepted` finding with severity high/critical, or
# ANY composite/chain finding — and no others (bounded so cost stays controlled). Such a finding carrying
# only ONE model's verdict ⇒ WARN pre-report, HARD once a report exists (same escalation shape).
_SECONDARY_REQUIRED_SEVERITIES = {"critical", "high"}


def _secondary_verdict_present(eng: Path, f: dict) -> bool:
    """True iff a cross-model second verdict exists for this finding — inline `secondary_review{}` with a
    verdict+reviewer, or a sidecar `reviews/<id>.secondary.verdict.json` (root or per-skill)."""
    sr = f.get("secondary_review")
    if isinstance(sr, dict) and sr.get("verdict") and sr.get("reviewer"):
        return True
    fid = f.get("id")
    if not fid:
        return False
    cands = [eng / "reviews" / f"{fid}.secondary.verdict.json"] + \
        sorted(eng.glob(f"*/reviews/{fid}.secondary.verdict.json"))
    for vp in cands:
        if vp.is_file():
            try:
                vd = json.loads(vp.read_text(encoding="utf-8")) or {}
            except Exception:  # noqa: BLE001
                continue
            if vd.get("verdict") and vd.get("reviewer"):
                return True
    return False


def _secondary_review_check(eng: Path, findings: list) -> tuple:
    """(hard_errors, warnings) for the cross-model second-verification gate (R3)."""
    armed = _gates_armed(eng, findings)
    hard, warns = [], []
    for f in findings:
        if not isinstance(f, dict):
            continue
        is_chain = bool(f.get("composite") or f.get("_composite"))
        verdict, _ = _review_of(f, eng)
        sev = str(f.get("severity", "")).lower()
        in_scope = is_chain or (verdict == "accepted" and sev in _SECONDARY_REQUIRED_SEVERITIES)
        if not in_scope or _secondary_verdict_present(eng, f):
            continue
        fid = f.get("id", "<no-id>")
        what = "composite/chain finding" if is_chain else f"accepted {sev}-severity finding"
        msg = (f"{fid} ({what}) carries only one model's verdict — no cross-model secondary_review. Run "
               f"the model-pinned adversarial-verify reviewer and record its verdict in secondary_review "
               f"(or reviews/{fid}.secondary.verdict.json)")
        if armed:
            hard.append("secondary-review gate (report present → a High/Critical accepted finding or any "
                        f"chain needs a cross-model second verdict): {msg}")
        else:
            warns.append(msg + " [becomes a hard gate once a report exists]")
    return hard, warns


# --- Cross-model EXHAUSTION-ADVERSARY HARD gate (disprove "engagement complete") ----------------- #
# The mechanical gate proves only "no failure the gate knows how to detect"; the per-class `*-verify`
# reviewers and the recall audit face PRECISION + the recall rules they HAVE. NONE of them disproves the
# top-level claim that the engagement is COMPLETE / the class is EXHAUSTED — and a same-model "are we done?"
# check is worthless (the model that decided it was done will agree with itself). The model-pinned,
# cross-model `exhaustion-adversary` agent (a DIFFERENT model than the executor + its same-model `*-verify`
# reviewer, fresh context, default stance "there IS a gap") hunts the gaps the deterministic gates can't
# see — a category attempted/done with no depth substance, a surface marked tested with no evidence
# artifact, a `blocked` mark never re-driven, a signalled surface shallow-cleared, a feeder finding never
# chained — and writes runtime/exhaustion_review.json with a no_gaps_found / found_gaps verdict. Once the
# gates arm this REQUIRES that artifact, a no_gaps_found verdict, AND every gap it ever raised closed — else
# the engagement is NOT report-ready. Un-routable, exactly like the secondary-review gate: there is NO
# operator-accept hatch — only the cross-model adversary's OWN no_gaps_found concession passes it.
_EXHAUSTION_GAP_CLOSED = {"closed", "resolved", "redriven", "re-driven"}


def _load_exhaustion_review(eng: Path):
    """Parse runtime/exhaustion_review.json (the cross-model adversary's verdict), or None when
    absent/invalid. Fail-safe: a half-written verdict returns None (→ the gate treats it as missing, which
    HARD-fails once armed — a report must never ship over an unreadable exhaustion review)."""
    p = eng / "runtime" / "exhaustion_review.json"
    if not p.is_file():
        return None
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — a half-written verdict must never crash the gate
        return None
    return d if isinstance(d, dict) else None


def _exhaustion_open_gaps(review: dict) -> list:
    """Human-readable descriptions of the exhaustion gaps still OPEN — status not in the closed set (a bare
    gap with no status is OPEN; only a named-blocker close/resolve/redrive accounts for one). [] when every
    raised gap is accounted for."""
    out = []
    for g in (review.get("gaps") or []):
        if not isinstance(g, dict):
            continue
        status = str(g.get("status") or "open").strip().lower()
        if status in _EXHAUSTION_GAP_CLOSED:
            continue
        where = g.get("category") or g.get("host") or "?"
        what = str(g.get("gap") or g.get("type") or "unspecified gap").strip()
        rem = str(g.get("remediation") or "").strip()
        out.append(f"{where}: {what}" + (f" -> {rem}" if rem else ""))
    return out


def _exhaustion_review_check(eng: Path, findings: list) -> tuple:
    """(hard_errors, warnings) for the cross-model exhaustion-adversary gate. HARD once the gates arm: a
    report must not ship unless runtime/exhaustion_review.json is present with verdict=no_gaps_found AND no
    still-open gap (the cross-model adversary could not disprove 'engagement complete'). A missing/unreadable
    artifact, a found_gaps verdict, or any open gap FAILS; before the gates arm it is a warning only.
    Un-routable — there is NO operator-accept hatch (mirrors _secondary_review_check): only the adversary's
    own no_gaps_found verdict passes it."""
    armed = _gates_armed(eng, findings)
    review = _load_exhaustion_review(eng)
    hint = ("run the model-pinned cross-model `exhaustion-adversary` agent (it writes "
            "runtime/exhaustion_review.json); only a no_gaps_found verdict with every gap closed is "
            "report-ready")

    def _wrap(msg):
        if armed:
            return (["exhaustion-adversary gate (report present → the cross-model adversary must be unable "
                     f"to disprove 'engagement complete'): {msg}"], [])
        return ([], [msg + " [becomes a hard gate once a report exists]"])

    if review is None:
        return _wrap("no cross-model exhaustion review — the 'engagement complete / class exhausted' claim "
                     f"was never independently disproved on a different model. {hint}")
    verdict = str(review.get("verdict") or "").strip().lower()
    open_gaps = _exhaustion_open_gaps(review)
    if verdict == "no_gaps_found" and not open_gaps:
        return ([], [])
    if verdict != "no_gaps_found":
        shown = ("; ".join(open_gaps[:6]) + (" …" if len(open_gaps) > 6 else "")) if open_gaps \
            else "no open gaps listed"
        return _wrap(f"exhaustion review verdict is {verdict or 'missing'!r} (not 'no_gaps_found') — the "
                     f"adversary found the engagement NOT exhausted ({shown}). Re-drive those gaps, then "
                     "re-run the adversary until it returns no_gaps_found.")
    # verdict says no_gaps_found but gaps remain open — an inconsistent verdict (a prior found_gap not closed)
    shown = "; ".join(open_gaps[:6]) + (" …" if len(open_gaps) > 6 else "")
    return _wrap(f"exhaustion review claims 'no_gaps_found' but {len(open_gaps)} gap(s) are still OPEN "
                 f"({shown}) — re-drive each gap (or record a named blocker) before report.")


def _exhaustion_review_hard_errors(eng: Path, findings: list) -> list:
    """HARD exhaustion-adversary gate (named entry point; mirrors _secondary_review_check's hard half):
    the open-exhaustion-gap / missing-verdict conditions a report must not ship over. [] until the gates
    arm."""
    return _exhaustion_review_check(eng, findings)[0]


# --- Cross-model DIVERSITY-VISIBILITY check (roadmap L-H): MEASURE what the `model:` pin ASSERTS ----- #
# The exhaustion-adversary gate above REQUIRES the cross-model verdict artifact, but it can only check the
# artifact EXISTS with verdict=no_gaps_found — never which model actually PRODUCED it. The framework ASSERTS
# cross-model diversity via a frontmatter `model:` pin (the adversary is pinned to a DIFFERENT model than the
# executors + their `*-verify` reviewers), but the ACTUALLY DISPATCHED model is otherwise recorded nowhere, so
# when a safeguard terminates every subagent of one model and they all silently fall back to the SAME model,
# cross-model collapses to same-model and this gate still passes. runtime/model_ledger.json records the model
# each agent ACTUALLY ran on; this check MEASURES whether the adversary/reviewers genuinely ran on a different
# model family than the executors, and surfaces "diversity unavailable" as a VISIBLE WARNING + a recorded
# deliverable fact. It is a WARNING, NOT a hard fail: a safeguard-blocked alternate model is a documented
# limitation, not a defect — the point is to surface it, never a silent same-model pass. It does NOT touch the
# exhaustion hard-gate (no_gaps_found stays the pass condition).
def _model_diversity_check(eng: Path, findings: list) -> tuple:
    """(warnings, summary) for the cross-model diversity-visibility check. NEVER returns a hard error.

    Once the gates arm (a report exists / the run is terminal) it WARNS — never fails — when:
      * runtime/model_ledger.json is ABSENT while a report exists (the actual dispatched model was never
        recorded, so diversity could not be MEASURED — it may have silently collapsed to same-model); or
      * the model ledger shows the exhaustion-adversary ran on the SAME model family as the executors (the
        same-model collapse) — a documented limitation, surfaced, not a silent pass; AND
      * (a stronger warning, independent of the above) the exhaustion_review's self-reported `model` field
        DISAGREES with the adversary's family in the model ledger — the asserted cross-model claim ≠ what ran.

    Before the gates arm the check is silent (a non-report engagement is unaffected). `summary` is the recorded
    deliverable fact (the diversity assessment + whether a warning fired), surfaced in the JSON + a summary
    line regardless of arming."""
    ml = _try_import_model_ledger()
    if not ml:
        return [], {"available": None, "warned": False,
                    "reason": "scripts/model_ledger.py not importable — cross-model diversity not measured"}
    try:
        assessment = ml.diversity_assessment(eng)
    except Exception:  # noqa: BLE001 — a diversity read must never crash the completion gate
        return [], {"available": None, "warned": False,
                    "reason": "model ledger unreadable — cross-model diversity not measured"}

    summary = dict(assessment)
    summary["available"] = assessment.get("cross_model_available")
    summary["warned"] = False
    summary["self_report_mismatch"] = False

    armed = _gates_armed(eng, findings)
    if not armed:
        # Mid-hunt: diversity is legitimately not yet decided — stay silent (a non-report engagement is
        # unaffected). Still surface the assessment as a recorded fact.
        return [], summary

    warnings = []
    ledger_present = (eng / "runtime" / "model_ledger.json").is_file()
    if not ledger_present:
        warnings.append(
            "cross-model diversity (model-ledger): no runtime/model_ledger.json while a report exists — the "
            "ACTUAL dispatched model per agent was never recorded, so the `model:` pin's cross-model diversity "
            "could NOT be MEASURED (it may have silently collapsed to same-model, e.g. a safeguard terminating "
            "one model's subagents). Record each dispatch with scripts/model_ledger.py so this is a measured "
            "fact, not an assertion. [warning — a documented limitation, never a hard fail]")
        summary["warned"] = True
    elif not assessment.get("cross_model_available"):
        warnings.append(
            "cross-model diversity (model-ledger): UNAVAILABLE — " + str(assessment.get("reason"))
            + ". Surfaced as a recorded deliverable fact, NOT a silent same-model pass. [warning — a documented "
            "limitation, never a hard fail: the exhaustion gate's no_gaps_found pass condition is unchanged]")
        summary["warned"] = True

    # Stronger cross-check: the exhaustion_review SELF-REPORTS a `model` free-text field. If it disagrees with
    # what the ledger recorded the adversary actually ran on, the asserted cross-model claim ≠ measured reality.
    review = _load_exhaustion_review(eng)
    if review is not None and ledger_present:
        self_fam = ml.model_family(review.get("model"))
        adv_fam = assessment.get("adversary_model")
        if self_fam and adv_fam and self_fam != adv_fam:
            warnings.append(
                f"cross-model diversity (model-ledger): exhaustion_review.json SELF-REPORTS model family "
                f"'{self_fam}' but runtime/model_ledger.json recorded the adversary actually dispatched on "
                f"'{adv_fam}' — the self-reported cross-model claim DISAGREES with what ran (asserted ≠ "
                f"measured). Trust the ledger (the measured fact) and record the real adversary model. "
                f"[warning — never a hard fail]")
            summary["self_report_mismatch"] = True
            summary["warned"] = True
    return warnings, summary


# --- Deliverable-consistency HARD gate (R4): attestation bound to measured recall ---------------- #
# A report/attestation must not NARRATE a clean/hardened posture while the measured signals contradict it:
# the recall reviewer flagged unadjudicated gaps (reviews/recall_audit.verdict.json), or the run itself was
# degraded/failed (runtime/diagnostics.json outcome ∈ {degraded-empty, failed}). This is the shopware-style
# failure — "held the line / hardened" narrated over an incomplete/degraded audit. HARD once a report
# exists; silent before. The machine-filled "Assurance & Coverage" clause (skills/engagement-docs) is the
# fix that keeps the deliverable honest; this gate is its enforcement.
_CLEAN_POSTURE_RE = re.compile(
    r"(hardened|held the line|clean bill of health"
    r"|no\s+(?:confirmed\s+|exploitable\s+|material\s+|significant\s+|critical\s+|high[-\s]severity\s+)*"
    r"(?:vulnerabilit(?:y|ies)|findings?|issues?|weakness(?:es)?)\b"
    r"|(?:strong|robust|solid|good|secure)\s+(?:security\s+)?posture)",
    re.IGNORECASE)
# A recall-gap verdict that means the gap is ACCOUNTED FOR (a clean/adjudicated close or a carried caveat).
# Anything else (missing verdict, a real-miss marker, escalate/open/pending) is UNADJUDICATED.
_RECALL_ADJUDICATED = {"justified-clear", "justified", "justified-clean", "clean", "blocked",
                       "open-proof-gap", "accepted", "resolved", "closed", "re-hunted", "rehunted"}


def _recall_verdict_unadjudicated(eng: Path) -> list:
    """Human-readable descriptions of recall gaps in reviews/recall_audit.verdict.json that remain
    UNADJUDICATED (no verdict, or a real-miss/open marker not in the adjudicated set). [] when the file is
    absent/unreadable or every gap is accounted for."""
    p = eng / "reviews" / "recall_audit.verdict.json"
    if not p.is_file():
        return []
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return []
    if not isinstance(d, dict):
        return []
    out = []
    for g in (d.get("gaps") or []):
        if not isinstance(g, dict):
            continue
        v = str(g.get("verdict") or "").strip().lower()
        if v in _RECALL_ADJUDICATED:
            continue
        cat = g.get("category") or "?"
        typ = g.get("type") or "?"
        out.append(f"{cat} [{typ}]: verdict={v or 'none'}")
    # a gaps-less verdict file that still records real_misses is itself an unadjudicated signal
    if not d.get("gaps"):
        rm = d.get("real_misses")
        n = len(rm) if isinstance(rm, list) else (rm if isinstance(rm, int) else 0)
        if n:
            out.append(f"{n} recorded real_miss(es) with no per-gap adjudication")
    return out


def _deliverable_doc_paths(eng: Path) -> list:
    """The engagement's human deliverables that could assert a posture — report.md / attestation.md /
    summary.md at the engagement root and one level down (the reporting + engagement-docs OUT dirs)."""
    paths = []
    for name in ("report.md", "attestation.md", "summary.md"):
        paths.append(eng / name)
        paths.extend(sorted(eng.glob(f"*/{name}")))
    seen, out = set(), []
    for p in paths:
        key = str(p.resolve())
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def _deliverable_consistency_errors(eng: Path, findings: list) -> list:
    """HARD deliverable-consistency gate (R4) — active once the gates arm. [] until then."""
    if not _gates_armed(eng, findings):
        return []
    contradictions = []
    run = _latest_run(_load_diagnostics(eng))
    if isinstance(run, dict) and run.get("outcome") in ("degraded-empty", "failed"):
        reason = str(run.get("degraded_reason") or "").strip()
        contradictions.append(f"runtime/diagnostics.json latest run outcome is '{run['outcome']}'"
                              + (f" ({reason})" if reason else ""))
    unadj = _recall_verdict_unadjudicated(eng)
    if unadj:
        shown = "; ".join(unadj[:4]) + (" …" if len(unadj) > 4 else "")
        contradictions.append(f"{len(unadj)} unadjudicated recall gap(s) in "
                              f"reviews/recall_audit.verdict.json ({shown})")
    if not contradictions:
        return []
    errs = []
    for p in _deliverable_doc_paths(eng):
        if not p.is_file():
            continue
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            continue
        m = _CLEAN_POSTURE_RE.search(txt)
        if not m:
            continue
        rel = p.relative_to(eng)
        errs.append("deliverable-consistency gate (report present → a clean/hardened posture claim must "
                    f"match measured recall + run health): {rel} asserts a clean/hardened posture "
                    f"(\"{m.group(0).strip()}\") while {'; '.join(contradictions)} — correct the "
                    "machine-filled 'Assurance & Coverage' clause (coverage_ledger + recall_audit verdict "
                    "+ diagnostics) so the deliverable states the real coverage, or close/adjudicate the "
                    "gaps (reviews/recall_audit.verdict.json) / record the run outcome first")
    return errs


def validate_engagement(eng: Path, as_json: bool) -> bool:
    cvss_mod = _try_import_cvss()
    vrt_mod = _try_import_vrt()
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

    # White-box-shape gate (fix #3): a `scope.source` engagement MUST carry the app model + a populated
    # code-audit surface slice — a source grant with only black-box recon surface is a recall gap, not a
    # pass. Candidate→finding reconciliation (fix #6): every source_context candidate must become a finding
    # (candidate_refs) or be accounted for as a tested/skipped source-lead. Both no-op for black-box.
    whitebox_errors = _whitebox_shape_errors(eng)
    candidate_errors = _candidate_reconciliation_errors(eng, findings)

    # CVSS-drift gate (R7): a finding whose declared severity != recomputed CVSS rating (no
    # potential_severity) is drift — a warning while hunting, HARD once a report exists.
    cvss_errors, cvss_warns = _cvss_drift_check(eng, findings, cvss_mod)
    top_warnings.extend(cvss_warns)
    # VRT-governance gate (L-B): on a bug-bounty engagement (scope program.platform != none AND
    # program.taxonomy == vrt), every accepted in-scope reportable finding must carry a valid,
    # non-inflated VRT whose path resolves in the pinned taxonomy. No-op for an ordinary pentest. Warn
    # while hunting, HARD once a report exists — the gate that keeps a fabricated VRT from shipping.
    vrt_errors, vrt_warns = _vrt_governance_check(eng, findings, vrt_mod)
    top_warnings.extend(vrt_warns)
    # Independent-reproducible-evidence gate (R1): a confirmed/Medium+ reportable finding needs >=1
    # independent artifact (request_response/poc_script/screenshot/dom_capture/code_citation), never only
    # its own log/tool_output/analysis (circular). Warn while hunting, HARD once a report exists.
    evidence_errors, evidence_warns = _independent_evidence_check(eng, findings)
    top_warnings.extend(evidence_warns)
    # Cross-model second-verification gate (R3): a High/Critical accepted finding or any chain needs a
    # second, model-pinned (adversarial-verify) verdict. Warn while hunting, HARD once a report exists.
    secondary_errors, secondary_warns = _secondary_review_check(eng, findings)
    top_warnings.extend(secondary_warns)
    # Cross-model exhaustion-adversary gate (disprove "done"): once a report exists, the model-pinned
    # cross-model adversary must have been UNABLE to disprove "engagement complete" — a no_gaps_found verdict
    # (runtime/exhaustion_review.json) with every gap it raised closed. Warn while hunting, HARD at close.
    exhaustion_errors, exhaustion_warns = _exhaustion_review_check(eng, findings)
    top_warnings.extend(exhaustion_warns)
    # Cross-model DIVERSITY-VISIBILITY (roadmap L-H): MEASURE what the `model:` pin asserts. The exhaustion
    # gate above only checks the verdict artifact EXISTS, never which model produced it — so record the ACTUAL
    # dispatched model per agent (runtime/model_ledger.json) and WARN (never fail) when cross-model collapsed to
    # same-model, or the ledger is absent while a report exists. A WARNING + a recorded deliverable fact, never
    # a silent same-model pass; the exhaustion hard-gate's no_gaps_found pass condition is untouched.
    diversity_warns, diversity_summary = _model_diversity_check(eng, findings)
    top_warnings.extend(diversity_warns)
    # Deliverable-consistency gate (R4): a report/attestation must not assert a clean/hardened posture
    # while recall gaps are unadjudicated or the run was degraded/failed. HARD once a report exists.
    deliverable_errors = _deliverable_consistency_errors(eng, findings)

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
    # The verdict is BOUND to every hard gate (fix #9): a "complete/clean" PASS cannot be emitted while
    # any hard-error list is non-empty — so a human/subagent swarm cannot narrate "hardened" past an open
    # ledger, an untested source surface, or an unreconciled candidate.
    gate_ok = ((not failed) and (not coverage_errors) and (not review_errors)
               and (not dup_errors) and (not integrity_errors) and (not recall_errors)
               and (not chain_errors) and (not diagnostics_errors)
               and (not whitebox_errors) and (not candidate_errors)
               and (not cvss_errors) and (not vrt_errors) and (not evidence_errors)
               and (not secondary_errors) and (not exhaustion_errors)
               and (not deliverable_errors))

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
                          "whitebox_errors": whitebox_errors,
                          "candidate_reconciliation_errors": candidate_errors,
                          "cvss_drift_errors": cvss_errors,
                          "vrt_governance_errors": vrt_errors,
                          "independent_evidence_errors": evidence_errors,
                          "secondary_review_errors": secondary_errors,
                          "exhaustion_review_errors": exhaustion_errors,
                          "deliverable_consistency_errors": deliverable_errors,
                          "diversity": diversity_summary,
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
        if whitebox_errors:
            print("\n✗ white-box-shape gate FAILED (scope.source → an app model + a populated code-audit "
                  "surface slice are required):")
            for we in whitebox_errors:
                print(f"  - {we}")
        if candidate_errors:
            print("\n✗ candidate-reconciliation gate FAILED (scope.source → every source_context candidate "
                  "must become a finding or be accounted for):")
            for ce2 in candidate_errors:
                print(f"  - {ce2}")
        if cvss_errors:
            print("\n✗ cvss-drift gate FAILED (a report is present, so a finding's severity must match its "
                  "recomputed CVSS rating or be flagged demonstrated-vs-potential):")
            for cde in cvss_errors:
                print(f"  - {cde}")
        if vrt_errors:
            print("\n✗ VRT-governance gate FAILED (a bug-bounty finding carries no VRT, a fabricated VRT "
                  "path, or an inflated priority):")
            for vge in vrt_errors:
                print(f"  - {vge}")
        if evidence_errors:
            print("\n✗ independent-evidence gate FAILED (a confirmed/Medium+ finding cites no reproducible "
                  "independent artifact — circular evidence):")
            for eve in evidence_errors:
                print(f"  - {eve}")
        if secondary_errors:
            print("\n✗ secondary-review gate FAILED (a High/Critical accepted finding or a chain lacks a "
                  "cross-model second verdict):")
            for sre in secondary_errors:
                print(f"  - {sre}")
        if exhaustion_errors:
            print("\n✗ exhaustion-adversary gate FAILED (the cross-model adversary was not run, or it could "
                  "not confirm the engagement is complete / the class exhausted):")
            for exe in exhaustion_errors:
                print(f"  - {exe}")
        if deliverable_errors:
            print("\n✗ deliverable-consistency gate FAILED (a deliverable asserts a clean/hardened posture "
                  "the measured recall / run health contradicts):")
            for dle in deliverable_errors:
                print(f"  - {dle}")
        # Cross-model diversity (roadmap L-H) — a recorded, VISIBLE deliverable fact (never a hard gate):
        # was the `model:` pin's cross-model diversity actually achieved, or did it collapse to same-model?
        _div_mark = "✓" if diversity_summary.get("available") else ("⚠" if diversity_summary.get("warned") else "ℹ")
        print(f"\n{_div_mark} cross-model diversity: {diversity_summary.get('reason', '(not measured)')}")
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
              f"error(s), {len(whitebox_errors)} white-box-shape error(s), {len(candidate_errors)} "
              f"candidate-reconciliation error(s), {len(cvss_errors)} cvss-drift error(s), "
              f"{len(vrt_errors)} VRT-governance error(s), "
              f"{len(evidence_errors)} independent-evidence error(s), {len(secondary_errors)} "
              f"secondary-review error(s), {len(exhaustion_errors)} exhaustion-adversary error(s), "
              f"{len(deliverable_errors)} deliverable-consistency error(s), "
              f"{len(all_warnings)} warning(s).")
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
        if whitebox_errors:
            print("A source-granted (scope.source) engagement lacks its white-box model / source surface => "
                  "write code-audit/app_model.json and run scripts/surface.py --plan so the code-audit surface "
                  "slice is enumerated + tested, before reporting.")
        if candidate_errors:
            print("A source_context candidate was never confirmed/refuted as a finding nor accounted for => "
                  "cite it in a finding's candidate_refs, or mark its source-lead surface tested/skipped, "
                  "before reporting.")
        if cvss_errors:
            print("A finding's declared severity contradicts its recomputed CVSS vector => fix the "
                  "vector/severity (don't hand-override the score), or set potential_severity "
                  "(demonstrated-vs-potential), before reporting.")
        if vrt_errors:
            print("A bug-bounty (program.taxonomy=vrt) finding is missing its VRT, points at a "
                  "fabricated VRT path, or claims an inflated priority => stamp/repair finding.vrt with a "
                  "real path (python scripts/vrt.py --resolve ...) and justify any elevation with "
                  "priority_basis=argued-elevation + a priority_rationale, before reporting.")
        if evidence_errors:
            print("A confirmed/Medium+ finding rests on circular evidence (its own log/tool_output/analysis) "
                  "=> add a reproducible INDEPENDENT artifact (request_response/poc_script/screenshot/"
                  "dom_capture/code_citation), or lower severity/confidence, before reporting.")
        if secondary_errors:
            print("A High/Critical accepted finding or a chain has only one model's verdict => run the "
                  "model-pinned adversarial-verify reviewer and record its secondary_review before reporting.")
        if exhaustion_errors:
            print("The 'engagement complete / class exhausted' claim was never independently disproved on a "
                  "different model => run the model-pinned cross-model exhaustion-adversary (it writes "
                  "runtime/exhaustion_review.json); re-drive every found_gap until it returns no_gaps_found.")
        if deliverable_errors:
            print("A deliverable narrates a clean/hardened posture the measured recall/run health "
                  "contradicts => correct the 'Assurance & Coverage' clause, or adjudicate the recall gaps / "
                  "record the real run outcome, before shipping the report/attestation.")
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
