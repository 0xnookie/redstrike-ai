#!/usr/bin/env python3
"""
console.py -- serve the Redstrike web console against your engagements.

The console (console/) is a static web UI over the engagement data model. This
launcher builds it and feeds it the JSON real engagements produce.

    python scripts/console.py                       # ALL engagements under engagements/
    python scripts/console.py engagements/          # same (explicit)
    python scripts/console.py engagements/<client>-<date>/   # just one

Point it at the `engagements/` directory (the default) and it discovers every
engagement inside, serves a manifest, and lets you switch between them in the UI
(Engagements page / ⌘K) — one launch, all engagements. Point it at a single
engagement dir to serve just that one.

For each engagement it searches (recursively) for the files the skills emit and
serves them under per-engagement routes the console fetches on open:

  findings_consolidated.json  (reporting)               -> /e/<id>/findings_consolidated.json
  host_discovery.json         (host-discovery)          -> /e/<id>/host_discovery.json
  content.json                (content-discovery)       -> /e/<id>/content.json
  http_history.json           (proxy-context)           -> /e/<id>/http_history.json
  notebook.json               (notebook)                -> /e/<id>/notebook.json
  chains.json                 (attack-chain-discovery)  -> /e/<id>/attack_chains.json
  scope.yaml / scope.json     (engagement root)         -> /e/<id>/scope.json

plus a js-analysis manifest + the analyzed JS files themselves (so the console's
asset detail can list and open what recon pulled per host):

  js-analysis/**             (js-analysis)             -> /e/<id>/js_analysis.json  (computed listing)
                                                       -> /e/<id>/js_recon.json     (computed: parsed findings/*.jsonl + site summary)
                                                       -> /e/<id>/js/<rel>          (raw file, correct Content-Type)

plus a `/engagements.json` manifest (one entry per engagement, with parsed scope
+ a reportable-severity summary computed server-side). scope.yaml is converted to
JSON on the fly (PyYAML if available, else a small built-in reader).
"""
import argparse
import http.server
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONSOLE = ROOT / "console"
OUT = CONSOLE / "out"

# scripts/ on sys.path so the shared structural validator imports whether this file is run as a
# script (python scripts/console.py) or imported as a module (e.g. by the tests).
_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))
import structvalidate  # noqa: E402

# canonical name -> candidate filenames the skills may use (first match wins, shallowest)
WANTED = {
    "findings_consolidated.json": ["findings_consolidated.json"],
    "host_discovery.json": ["host_discovery.json"],
    "attack_chains.json": ["attack_chains.json", "chains.json"],
    "coverage_ledger.json": ["coverage_ledger.json"],
    "cve_intel.json": ["cve_intel.json"],
    "content.json": ["content.json"],
    "http_history.json": ["http_history.json"],
    "notebook.json": ["notebook.json"],
    "diagnostics.json": ["diagnostics.json"],
    "reasoning_trace.json": ["reasoning_trace.json"],
    # white-box (source-audit) surfaces the console's Source Map / Source Assets views read.
    # surface_ledger.json sits at the engagement root; source_context.json is nested under
    # source-audit/ — its canonical key carries that served sub-path so resolve() maps
    # /e/<id>/source-audit/source_context.json straight to it.
    "surface_ledger.json": ["surface_ledger.json"],
    "source-audit/source_context.json": ["source_context.json"],
    "scope.json": ["scope.json"],
}


def ensure_build(force: bool) -> None:
    npm = "npm.cmd" if os.name == "nt" else "npm"
    if not (CONSOLE / "node_modules").exists():
        print("· installing console dependencies (first run)…")
        subprocess.run([npm, "--prefix", str(CONSOLE), "install"], check=True)
    if force or not (OUT / "index.html").exists():
        print("· building the console…")
        subprocess.run([npm, "--prefix", str(CONSOLE), "run", "build"], check=True)


# Heavy, non-artifact subtrees that are NEVER searched for engagement files. A
# white-box engagement embeds a full source checkout under source/ (tens of
# thousands of files — Shopware's is 29,587); globbing it on every request made a
# single findings fetch take ~45s and stacked the 15s manifest poll into a
# starvation spiral (findings never rendered). Skills only ever write served
# artifacts OUTSIDE these dirs (source-audit/, code-audit/, findings/, report/ …),
# so pruning them is safe and ~100x faster. Dot-dirs are skipped too.
_PRUNE_DIRS = {"source", ".git", "node_modules", "vendor", "__pycache__"}


def _walk_pruned(root: Path):
    """os.walk(root), top-down, never descending into _PRUNE_DIRS or dot-dirs, so an
    embedded source checkout is never walked. Yields (Path(dirpath), filenames)."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _PRUNE_DIRS and not d.startswith(".")]
        yield Path(dirpath), filenames


def _shallowest(root: Path, name: str):
    """Shallowest file named `name` under `root`, skipping heavy non-artifact
    subtrees. Deterministic: ties at equal depth break on the full path string."""
    hits = [dirpath / name for dirpath, filenames in _walk_pruned(root) if name in filenames]
    hits.sort(key=lambda p: (len(p.parts), str(p)))
    return hits[0] if hits else None


def _js_dir(engagement: Path):
    """The engagement's js-analysis directory (shallowest match), if any."""
    hits = [dirpath for dirpath, _ in _walk_pruned(engagement) if dirpath.name == "js-analysis"]
    hits.sort(key=lambda p: (len(p.parts), str(p)))
    return hits[0] if hits else None


def js_analysis_manifest(engagement: Path) -> dict:
    """List the JS files recon analyzed, grouped by their per-host subdir.

    The js-analysis skill writes the scripts it pulled into <eng>/js-analysis/<host-ish>/.
    We expose a flat listing (dir + name + rel + size) so the console's asset detail can
    show "what was analyzed on this host" and link each file to its raw route below."""
    base = _js_dir(engagement)
    files = []
    if base:
        for p in sorted(base.rglob("*")):
            if not p.is_file() or p.name.startswith("."):
                continue
            rel = p.relative_to(base)
            parent = str(rel.parent)
            try:
                size = p.stat().st_size
            except OSError:
                size = None
            files.append({
                "dir": "" if parent == "." else parent,
                "name": p.name,
                "rel": str(rel),
                "bytes": size,
            })
    return {"files": files}


def _read_jsonl(path: Path, cap: int = 4000):
    """Parse a findings/*.jsonl file tolerantly — one JSON object per line.

    Returns (rows up to `cap`, total valid rows seen). Blank/garbage lines are
    skipped so a half-written stream never breaks the view."""
    rows, total = [], 0
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                total += 1
                if len(rows) < cap:
                    rows.append(obj)
    except OSError:
        return [], 0
    return rows, total


_JS_STREAMS = ("endpoints", "params", "apis", "secrets", "gadgets", "libraries")


def js_recon_report(engagement: Path) -> dict:
    """Aggregate the js-analysis FINDINGS into one payload for the JS Recon view.

    The js-analysis skill writes one out/<site>/ tree per in-scope site, each with
    findings/{endpoints,params,apis,secrets,gadgets,libraries}.jsonl +
    analysis/site-summary.md + report.md. We locate each site by its findings/ dir
    (robust to the out/ wrapper), parse the JSONL line-by-line, and fold in the
    per-site summary. Secrets are already redacted at the source (match_redacted);
    this only relays what the skill wrote."""
    base = _js_dir(engagement)
    sites = []
    if base:
        seen = set()
        for findings_dir in sorted(base.rglob("findings")):
            if not findings_dir.is_dir():
                continue
            site_root = findings_dir.parent
            key = str(site_root.resolve())
            if key in seen:
                continue
            seen.add(key)
            site = {"site": site_root.name, "counts": {}, "truncated": {}}
            for name in _JS_STREAMS:
                rows, total = _read_jsonl(findings_dir / f"{name}.jsonl")
                site[name] = rows
                site["counts"][name] = total
                if total > len(rows):
                    site["truncated"][name] = True
            summary = site_root / "analysis" / "site-summary.md"
            try:
                if summary.is_file():
                    site["summary_md"] = summary.read_text(encoding="utf-8", errors="replace")[:200_000]
            except OSError:
                pass
            site["has_report"] = (site_root / "report.md").is_file()
            if any(site["counts"].get(n) for n in _JS_STREAMS) or site.get("summary_md") or site["has_report"]:
                sites.append(site)
    sites.sort(key=lambda s: s["site"])
    totals = {n: sum(s["counts"].get(n, 0) for s in sites) for n in _JS_STREAMS}
    return {"sites": sites, "totals": totals, "site_count": len(sites)}


# --- serve-time structural validation (Fix #5) ------------------------------
# Producers can drift from the _contract schemas (the js-analysis library->name /
# provider->provider_meta / note->context / count->snippet regression blanked the JS Recon view).
# scripts/validate.py only lints the schema FILES + review.md wiring; the runtime gate validates
# findings.json only; this console served everything RAW. So we validate each served artifact
# against its _contract schema here and attach a NON-FATAL `_contract_violations[]` to the payload
# the frontend can surface, dropping only structurally-unusable rows so one bad row can't blank the
# whole view (degraded, not blank).
CONTRACT = ROOT / "skills" / "_contract"

# canonical served name -> (schema file, lenient). The authored, drift-locking schemas (js streams,
# content) run strict so a drifted alias key / missing canonical key is caught. The pre-existing
# schemas validate LENIENTLY: type/enum/range of the fields that are PRESENT only — a benign extra
# key or a concurrently-added field never flags, but a genuinely wrong shape (cve_intel.source not an
# array, epss outside 0..1, reachable not an enum value) still does. diagnostics is lenient on
# purpose: its schema is being extended concurrently, so unknown/optional fields must be tolerated.
_SV_CONFIG = {
    "findings_consolidated.json": ("findings_consolidated.schema.json", True),
    "host_discovery.json": ("host_discovery.schema.json", True),
    "attack_chains.json": ("attack_chain.schema.json", True),
    "coverage_ledger.json": ("coverage_ledger.schema.json", True),
    "cve_intel.json": ("cve_intel.schema.json", True),
    "content.json": ("content.schema.json", False),
    "http_history.json": ("http_history.schema.json", True),
    "notebook.json": ("notebook.schema.json", True),
    "diagnostics.json": ("diagnostics.schema.json", True),
    "reasoning_trace.json": ("reasoning_trace.schema.json", True),
    "scope.json": ("scope.schema.json", True),
    "js_recon.json": ("js_findings.schema.json", False),
}

# js_recon stream key -> the $defs entry in js_findings.schema.json each row validates against.
_JS_STREAM_DEF = {
    "endpoints": "endpoint", "params": "param", "apis": "api",
    "secrets": "secret", "gadgets": "gadget", "libraries": "library",
}


def _json_bytes(obj) -> bytes:
    return json.dumps(obj, default=str).encode("utf-8")


def _attach(obj, violations):
    """Attach `_contract_violations` to a dict payload (always present — even when empty — so the key
    is a stable contract the frontend can read). A non-dict payload passes through unchanged."""
    if isinstance(obj, dict):
        obj["_contract_violations"] = violations
    return obj


def _validate_rows(rows, schema, def_name, path_prefix, lenient, sink):
    """Validate each row against #/$defs/<def_name>, prefixing its violation paths with
    `<path_prefix>[i]`. DROP a row that isn't an object (coerce — so one unusable row can't break a
    .map over the stream); keep rows that merely have field violations (recorded, still rendered).
    Returns the kept rows."""
    if not isinstance(rows, list) or not isinstance(schema, dict):
        return rows
    sub = {"$defs": schema.get("$defs", {}), "$ref": f"#/$defs/{def_name}"}
    kept = []
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            sink.append({"path": f"{path_prefix}[{i}]", "expected": "object",
                         "got": structvalidate.typename(row)})
            continue
        for v in structvalidate.validate(row, sub, lenient=lenient):
            tail = f".{v['path']}" if v["path"] else ""
            sink.append({"path": f"{path_prefix}[{i}]{tail}",
                         "expected": v["expected"], "got": v["got"]})
        kept.append(row)
    return kept


def _validate_js_recon(obj):
    """Validate each site's six findings streams against the js_findings $defs (STRICT: the canonical
    field names are locked, so library->name / provider->provider_meta drift is caught)."""
    schema = structvalidate.load_schema(CONTRACT, "js_findings.schema.json") or {}
    violations = []
    if isinstance(obj, dict) and isinstance(obj.get("sites"), list):
        for si, site in enumerate(obj["sites"]):
            if not isinstance(site, dict):
                continue
            for stream, dn in _JS_STREAM_DEF.items():
                if isinstance(site.get(stream), list):
                    site[stream] = _validate_rows(
                        site[stream], schema, dn, f"sites[{si}].{stream}", False, violations)
    return _attach(obj, violations)


def _validate_findings(obj):
    """Normalize to the `{findings:[...]}` object form the frontend also accepts, validate the
    envelope (lenient) + each finding against finding.schema $defs/finding (lenient), dropping a
    non-object finding so one bad row can't blank the report."""
    env = structvalidate.load_schema(CONTRACT, "findings_consolidated.schema.json")
    fsch = structvalidate.load_schema(CONTRACT, "finding.schema.json")
    violations = []
    if isinstance(obj, list):
        obj = {"findings": obj}
    if not isinstance(obj, dict):
        return _attach({"findings": []}, violations)
    if env is not None:
        violations.extend(structvalidate.validate(obj, env, lenient=True))
    if isinstance(obj.get("findings"), list):
        obj["findings"] = _validate_rows(obj["findings"], fsch, "finding", "findings", True, violations)
    return _attach(obj, violations)


def _validate_history(obj):
    """Normalize a legacy flat array to `{exchanges:[...]}` and validate each exchange (lenient)."""
    schema = structvalidate.load_schema(CONTRACT, "http_history.schema.json")
    violations = []
    if isinstance(obj, list):
        obj = {"exchanges": obj}
    if not isinstance(obj, dict):
        return _attach({"exchanges": []}, violations)
    if isinstance(obj.get("exchanges"), list):
        obj["exchanges"] = _validate_rows(obj["exchanges"], schema, "exchange", "exchanges", True, violations)
    return _attach(obj, violations)


def _validate(name: str, obj):
    """Validate a served artifact against its _contract schema and return the (possibly normalized)
    payload with a NON-FATAL `_contract_violations[]` attached. Never raises; an unmapped artifact or
    a missing schema passes the payload through untouched so validation can never blank a view."""
    if obj is None:
        return obj
    if name == "js_recon.json":
        return _validate_js_recon(obj)
    if name == "findings_consolidated.json":
        return _validate_findings(obj)
    if name == "http_history.json":
        return _validate_history(obj)
    cfg = _SV_CONFIG.get(name)
    if cfg is None:
        return obj
    schema_file, lenient = cfg
    schema = structvalidate.load_schema(CONTRACT, schema_file)
    violations = structvalidate.validate(obj, schema, lenient=lenient) if schema is not None else []
    return _attach(obj, violations)


def _ctype_for(p: Path) -> str:
    return {
        ".js": "text/javascript; charset=utf-8",
        ".mjs": "text/javascript; charset=utf-8",
        ".cjs": "text/javascript; charset=utf-8",
        ".ts": "text/plain; charset=utf-8",
        ".json": "application/json",
        ".map": "application/json",
        ".css": "text/css; charset=utf-8",
        ".html": "text/html; charset=utf-8",
        ".txt": "text/plain; charset=utf-8",
    }.get(p.suffix.lower(), "text/plain; charset=utf-8")


def looks_like_engagement(d: Path) -> bool:
    # DIRECT-child signals only — a parent `engagements/` dir must NOT match itself
    # via a file nested inside one of its engagements.
    if not d.is_dir():
        return False
    return (
        (d / "scope.yaml").exists()
        or (d / "report").is_dir()
        or (d / "host-discovery").is_dir()
        or (d / "report" / "findings_consolidated.json").exists()
    )


def discover(target: Path) -> list[Path]:
    """A single engagement dir, or every engagement under a parent dir."""
    if looks_like_engagement(target):
        return [target]
    engs = []
    for child in sorted(p for p in target.iterdir() if p.is_dir()):
        if child.name.startswith((".", "_")):
            continue
        if looks_like_engagement(child):
            engs.append(child)
    return engs


# Short-TTL per-engagement discovery cache. The console opens an engagement by
# fetching ~10 artifacts near-simultaneously, and polls the manifest every 15s; a
# cold files_for() walks the (pruned) tree once per wanted name, so without this the
# open-burst re-walks the same tree a dozen times. A 3s TTL collapses the burst into
# one walk while still surfacing a newly-written artifact within a few seconds. The
# GIL makes the plain-dict get/set safe enough under the threading server (a cold
# race just does an extra harmless walk).
_FILES_CACHE: dict = {}
_FILES_TTL = 3.0


def files_for(engagement: Path) -> dict:
    """canonical name -> source Path for one engagement (real files on disk only)."""
    key = str(engagement)
    now = time.monotonic()
    cached = _FILES_CACHE.get(key)
    if cached and (now - cached[0]) < _FILES_TTL:
        return cached[1]
    files = {}
    for canonical, candidates in WANTED.items():
        if canonical == "scope.json":
            continue  # scope is resolved separately (scope.yaml -> JSON in memory)
        for name in candidates:
            hit = _shallowest(engagement, name)
            if hit:
                files[canonical] = hit
                break
    _FILES_CACHE[key] = (now, files)
    return files


def scope_for(engagement: Path):
    """A scope dict for one engagement: a real scope.json if present, else scope.yaml."""
    sj = _shallowest(engagement, "scope.json")
    if sj:
        return _read_json(sj)
    sy = engagement / "scope.yaml"
    if not sy.exists():
        sy = _shallowest(engagement, "scope.yaml")
    return scope_yaml_to_json(sy) if (sy and sy.exists()) else None


def _read_json(path):
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _verdict(f: dict) -> str:
    """The reviewer's decision. `review.verdict` is the AUTHORITATIVE axis; the finding's
    `status` is derived from it (verify-base.md: accepted/blocked->verified, rejected->rejected,
    needs-evidence->open). When the inline review block is absent we fall back to deriving the
    verdict from status — lossy (a `blocked` finding reads back as `accepted`), but `_reportable`
    treats both the same, so the count is unaffected."""
    r = f.get("review") or {}
    if r.get("verdict"):
        return r["verdict"]
    st = f.get("status")
    return "rejected" if st == "rejected" else "accepted" if st == "verified" else ""


def _reportable(f: dict) -> bool:
    composite = bool(f.get("composite") or f.get("_composite"))
    return (not composite) and _verdict(f) in ("accepted", "blocked")


def _findings_list(path):
    d = _read_json(path)
    if isinstance(d, list):
        return d
    if isinstance(d, dict):
        return list(d.get("findings") or [])
    return None


def engagement_findings(eng: Path, files: dict):
    """The engagement's findings as a list, across the layouts the pipeline produces (mirrors
    verify_completion's discovery): the consolidated report if present, else a root findings.json,
    else the UNION of per-skill <eng>/<skill>/findings.json — so the console shows live findings
    before `reporting` has consolidated them. Returns (findings, consolidated?)."""
    cons = files.get("findings_consolidated.json")
    if cons:
        lst = _findings_list(cons)
        if lst is not None:
            return lst, True
    root = eng / "findings.json"
    if root.is_file():
        lst = _findings_list(root)
        if lst is not None:
            return lst, False
    union = []
    for p in sorted(eng.glob("*/findings.json")):
        part = _findings_list(p)
        if part:
            union.extend(part)
    return union, False


def summarize(eng: Path, files: dict) -> dict:
    """Reportable-severity counts + chain count, computed server-side for the list."""
    findings, _ = engagement_findings(eng, files)
    counts = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    total = 0
    for f in findings:
        if isinstance(f, dict) and _reportable(f):
            total += 1
            sev = f.get("severity")
            if sev in counts:
                counts[sev] += 1
    chains = 0
    cj = _read_json(files.get("attack_chains.json"))
    cons = _read_json(files.get("findings_consolidated.json"))
    if isinstance(cj, dict) and isinstance(cj.get("chains"), list):
        chains = len(cj["chains"])
    elif isinstance(cons, dict) and isinstance(cons.get("attack_chains"), list):
        chains = len(cons["attack_chains"])
    return {"findings": total, **counts, "chains": chains}


def _severity_counts(findings) -> dict:
    """Reportable-severity split in the report's `severity_counts` shape (critical/high/medium/
    low/info). Reuses `_reportable` — the same rule `summarize()` uses — so blocked/accepted
    non-composite findings count and rejected/needs-evidence ones don't."""
    counts = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        if isinstance(f, dict) and _reportable(f):
            sev = f.get("severity")
            if sev in counts:
                counts[sev] += 1
    return counts


def _scope_target(scope) -> str | None:
    """A human target string from a parsed scope, or None. Mirrors scope_yaml_to_json's precedence
    (an explicit `target`, else the first in-scope domain stripped of its wildcard, else the first
    in-scope URL) so it also yields something useful for a raw runtime/scope.json that carries no
    computed `target`. Never raises."""
    if not isinstance(scope, dict):
        return None
    t = scope.get("target")
    if t:
        return t
    insc = scope.get("in_scope") if isinstance(scope.get("in_scope"), dict) else {}
    doms = insc.get("domains") or []
    if doms:
        return str(doms[0]).lstrip("*.")
    urls = insc.get("urls") or []
    if urls:
        return str(urls[0])
    return None


def _computed_envelope(eng: Path, findings: list) -> dict:
    """Wrap the live per-skill union in a MINIMAL report-shaped envelope (engagement / target /
    generated_at / severity_counts / open_proof_gaps) so a pre-reporting engagement serves the same
    top-level shape a real findings_consolidated.json does — several frontend views read those
    header fields that a bare {findings} union would be missing. Never raises: an unreadable scope
    degrades to a null target, not a crash."""
    try:
        scope = scope_for(eng)
    except Exception:
        scope = None
    return {
        "engagement": eng.name,
        "target": _scope_target(scope),
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "severity_counts": _severity_counts(findings),
        "open_proof_gaps": [],
        "findings": findings,
    }


def _iso_z(v):
    """Normalize a window timestamp to the scope.yaml ISO-8601 'Z' form. PyYAML parses
    an ISO timestamp into a (tz-aware) datetime/date whose str() is '2026-01-01 00:00:00+00:00';
    the dependency-free reader keeps the raw 'YYYY-MM-DDTHH:MM:SSZ' string. Coerce both to the
    same ISO-8601 'Z' representation so the two code paths agree."""
    import datetime as _dt
    if isinstance(v, (_dt.datetime, _dt.date)):
        return v.isoformat().replace("+00:00", "Z")
    return str(v or "")


def scope_yaml_to_json(path: Path):
    """Read a scope.yaml into the console's scope.json shape. PyYAML if present."""
    try:
        import yaml  # type: ignore
        with open(path, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
    except Exception:
        doc = _minimal_scope_read(path)
    if not isinstance(doc, dict):
        return None

    def block(key):
        b = doc.get(key) or {}
        return {
            "domains": list(b.get("domains") or []),
            "cidrs": list(b.get("cidrs") or []),
            "urls": list(b.get("urls") or []),
        }

    win = doc.get("window") or {}
    domains = block("in_scope")["domains"]
    src = doc.get("source") if isinstance(doc.get("source"), dict) else None
    target = (domains[0].lstrip("*.") if domains else "") or (src or {}).get("repo_url") or doc.get("engagement", "")
    out = {
        "engagement": doc.get("engagement", ""),
        "target": target,
        "authorized_by": doc.get("authorized_by", ""),
        "window": {"start": _iso_z(win.get("start", "")), "end": _iso_z(win.get("end", ""))},
        "in_scope": block("in_scope"),
        "out_of_scope": block("out_of_scope"),
        "rules": doc.get("rules") or {},
        "notes": (doc.get("notes") or "").strip() if isinstance(doc.get("notes"), str) else "",
        "source": "scope.yaml",
    }
    # White-box source audit: surface the repo grant (cloned source under the engagement) so the
    # console can show an engagement is source-granted. Keyed `source_repo` to avoid colliding with
    # the `source: "scope.yaml"` provenance string above.
    if src:
        out["source_repo"] = {
            "repo_url": str(src.get("repo_url", "")),
            "local_path": str(src.get("local_path", "")),
            "commit": str(src.get("commit", "")),
            "branch": str(src.get("branch", "")),
        }
    return out


def _strip_inline_comment(s: str) -> str:
    """Drop a trailing YAML `#` comment without breaking a quoted value that contains '#'.
    A '#' opens a comment only at line start or after whitespace, and never inside quotes."""
    q = None
    for i, ch in enumerate(s):
        if q:
            if ch == q:
                q = None
        elif ch in ("'", '"'):
            q = ch
        elif ch == "#" and (i == 0 or s[i - 1] in " \t"):
            return s[:i]
    return s


def _minimal_scope_read(path: Path) -> dict:
    """Dependency-free fallback when PyYAML is unavailable. Parses top-level
    `key: value` scalars and one level of nested maps/lists under them — enough
    for engagement / authorized_by / window / in_scope / out_of_scope / rules."""
    doc: dict = {}
    section = None
    list_key = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = _strip_inline_comment(raw).rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        s = line.strip()
        if s.startswith("- "):
            if section is not None and list_key is not None:
                section.setdefault(list_key, []).append(s[2:].strip().strip("\"'"))
            continue
        if ":" not in s:
            continue
        key, _, val = s.partition(":")
        key, val = key.strip(), val.strip().strip("\"'")
        if indent == 0:
            list_key = None
            if val in ("", ">", "|"):
                section = {}
                doc[key] = section
            else:
                section = None
                doc[key] = val
        elif section is not None:
            if val in ("", ">", "|"):
                list_key = key
                section.setdefault(key, [])
            elif val == "[]":
                list_key = None
                section[key] = []          # inline empty list (e.g. `cidrs: []`)
            elif val == "{}":
                list_key = None
                section[key] = {}          # inline empty map
            else:
                list_key = None
                section[key] = val
    return doc


def run_info(eng: Path) -> dict:
    """Whether this engagement has an autonomous-run log, and when it was last written.
    The console reads "written moments ago" as a run still going — the one liveness signal
    that also covers runs this server didn't launch (e.g. from a terminal)."""
    log = eng / "runtime" / "autorun.jsonl"
    if not log.is_file():
        return {"log": False, "updated": None}
    ts = datetime.fromtimestamp(log.stat().st_mtime, timezone.utc)
    return {"log": True, "updated": ts.isoformat().replace("+00:00", "Z")}


def coverage_progress(files: dict):
    """Phase progress from the coverage ledger: of the categories in phase (not n/a), how many
    are no longer pending (attempted / skipped-with-reason / blocked / pipeline)."""
    led = _read_json(files.get("coverage_ledger.json"))
    cats = led.get("categories") if isinstance(led, dict) else None
    if not isinstance(cats, list):
        return None
    in_phase = [c for c in cats if isinstance(c, dict) and c.get("status") != "n/a"]
    if not in_phase:
        return None
    pending = sum(1 for c in in_phase if c.get("status") == "pending")
    return {"done": len(in_phase) - pending, "total": len(in_phase)}


def diagnostics_summary(files: dict):
    """Reliability summary from the latest diagnostics run (runtime/diagnostics.json): the run's
    `outcome` + `degraded_reason` + overall transport status, so the console can surface a
    degraded/blocked engagement ("produced nothing: <reason>") instead of a false green 100%.
    None when no diagnostics file / no runs — the console then shows no reliability banner."""
    diag = _read_json(files.get("diagnostics.json"))
    runs = diag.get("runs") if isinstance(diag, dict) else None
    if not isinstance(runs, list) or not runs or not isinstance(runs[-1], dict):
        return None
    run = runs[-1]
    th = run.get("transport_health") if isinstance(run.get("transport_health"), dict) else {}
    overall = th.get("overall") if isinstance(th.get("overall"), dict) else {}
    return {
        "outcome": run.get("outcome"),
        "degraded_reason": run.get("degraded_reason"),
        "findings_count": run.get("findings_count"),
        "transport_status": overall.get("status"),
        "worst_host": overall.get("worst_host"),
        "block_rate": overall.get("block_rate"),
    }


def manifest_entries(target: Path) -> list:
    """One entry per discovered engagement — rebuilt live on each request, so a
    console left running reflects a scan that finished after launch."""
    entries = []
    for eng in discover(target):
        files = files_for(eng)
        cons = _read_json(files.get("findings_consolidated.json"))
        scope = scope_for(eng)
        has = {k: (k in files) for k in WANTED}
        has["scope.json"] = scope is not None
        diag = diagnostics_summary(files)
        entries.append({
            "id": eng.name,
            "scope": scope,
            "summary": summarize(eng, files),
            "generated": (cons.get("generated") if isinstance(cons, dict) else None),
            "has": has,
            "run": run_info(eng),
            "progress": coverage_progress(files),
            "outcome": (diag.get("outcome") if diag else None),
            "degraded_reason": (diag.get("degraded_reason") if diag else None),
            "diagnostics": diag,
        })
    return entries


def make_handler(target: Path):
    def resolve(clean: str):
        """Return ('json', bytes) | ('file', Path) | None for a dynamic route."""
        if clean == "/engagements.json":
            body = json.dumps({"engagements": manifest_entries(target)}, default=str)
            return ("json", body.encode("utf-8"))
        if clean.startswith("/e/"):
            parts = clean[len("/e/"):].split("/", 1)
            if len(parts) != 2:
                return None
            eid, name = parts
            eng = next((e for e in discover(target) if e.name == eid), None)
            if not eng:
                return None
            if name == "scope.json":
                scope = scope_for(eng)
                return ("json", _json_bytes(_validate("scope.json", scope))) if scope else None
            if name == "js_analysis.json":
                return ("json", _json_bytes(js_analysis_manifest(eng)))  # file listing — no _contract schema
            if name == "js_recon.json":
                return ("json", _json_bytes(_validate("js_recon.json", js_recon_report(eng))))
            if name.startswith("js/"):
                base = _js_dir(eng)
                if not base:
                    return None
                base = base.resolve()
                tgt = (base / name[len("js/"):]).resolve()
                # strict: tgt must be a real file INSIDE the js-analysis dir (no traversal)
                if tgt.is_file() and (tgt == base or base in tgt.parents):
                    return ("file", tgt, _ctype_for(tgt))
                return None
            if name == "findings_consolidated.json":
                files = files_for(eng)
                cons_path = files.get(name)
                # Prefer the consolidated report (keep ALL its keys — target / attack_chains /
                # severity_counts the frontend reads), else the live per-skill union (shown before
                # `reporting` runs). Both go through the validator.
                raw = _read_json(cons_path) if cons_path else None
                if not isinstance(raw, (list, dict)):
                    findings, _ = engagement_findings(eng, files)
                    if not findings:
                        return None
                    # Computed union (no on-disk report yet): wrap the live findings in a minimal
                    # report envelope so its top-level shape matches a real consolidated report.
                    raw = _computed_envelope(eng, findings)
                return ("json", _json_bytes(_validate("findings_consolidated.json", raw)))
            # every other canonical artifact: load + validate + serve JSON (was raw file). An
            # artifact with no _contract schema, or one that won't parse as JSON, falls back to the
            # raw file so nothing is ever hidden by validation.
            src = files_for(eng).get(name)
            if not src:
                return None
            if name in _SV_CONFIG:
                obj = _read_json(src)
                if obj is not None:
                    return ("json", _json_bytes(_validate(name, obj)))
            return ("file", src)
        return None

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=str(OUT), **k)

        def _serve_dynamic(self, body_only: bool) -> bool:
            r = resolve(self.path.split("?")[0])
            if r is None:
                return False
            kind, payload = r[0], r[1]
            # file routes may carry an explicit Content-Type (3rd element); JSON + legacy
            # file routes default to application/json (every legacy file route serves JSON).
            ctype = r[2] if len(r) > 2 else "application/json"
            try:
                data = payload if kind == "json" else Path(payload).read_bytes()
            except OSError:
                self.send_error(404)
                return True
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if not body_only:
                self.wfile.write(data)
            return True

        def do_GET(self):
            if not self._serve_dynamic(body_only=False):
                super().do_GET()

        def do_HEAD(self):
            if not self._serve_dynamic(body_only=True):
                super().do_HEAD()

        def _offline(self):
            # This is the READ-ONLY viewer: it implements no write verbs. A POST/PUT/DELETE/PATCH
            # means the console tried to reach the control plane (/api/*). The stdlib base handler
            # would answer an unimplemented method with a bare 501, which the console surfaces as a
            # confusing "HTTP 501". Answer with a plain (non-JSON) 404 instead — lib/control.ts maps
            # that to kind:"offline", so the UI shows how to start scripts/console_control.py.
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                n = 0
            if n > 0:
                try:
                    self.rfile.read(n)  # drain the request body so keep-alive stays sane
                except OSError:
                    pass
            self.send_error(404, "control plane not running (read-only viewer)")

        do_POST = _offline
        do_PUT = _offline
        do_DELETE = _offline
        do_PATCH = _offline

        def end_headers(self):
            self.send_header("Cache-Control", "no-store")
            super().end_headers()

        def log_message(self, *a):  # quiet
            pass

    return Handler


def port_in_use(port: int) -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Serve the Redstrike console against your engagements.")
    ap.add_argument("target", nargs="?", default=str(ROOT / "engagements"),
                    help="an engagement dir, or a directory of engagements (default: engagements/)")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--build", action="store_true", help="force a fresh console build")
    ap.add_argument("--open", action="store_true", help="open the console in a browser")
    ap.add_argument("--background", action="store_true", help="start detached, print the URL, and return")
    args = ap.parse_args()

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"error: path not found: {target}", file=sys.stderr)
        return 2

    url = f"http://localhost:{args.port}/"

    # idempotent: if something is already serving this port, don't start a second one
    if port_in_use(args.port):
        print(f"  console already serving at {url}")
        if args.open:
            _open_browser(url, wait_port=args.port)
        return 0

    if not discover(target):
        print(f"error: no engagements found under {target}", file=sys.stderr)
        return 2

    # background: re-spawn self detached (so callers like `redstrike run` don't block)
    if args.background:
        cmd = [sys.executable, str(Path(__file__).resolve()), str(target), "--port", str(args.port)]
        if args.build:
            cmd.append("--build")
        devnull = open(os.devnull, "wb")
        subprocess.Popen(cmd, stdout=devnull, stderr=devnull, start_new_session=True)
        print(f"  console (background) -> {url}")
        if args.open:
            _open_browser(url, wait_port=args.port)
        return 0

    ensure_build(args.build)
    entries = manifest_entries(target)
    print(f"\n  source     : {target}")
    print(f"  engagements: {len(entries)}")
    for e in entries:
        s = e["summary"]
        print(f"    · {e['id']:<40} {s['findings']} findings · {s['chains']} chains")
    print(f"\n  console    : {url}\n  (Ctrl+C to stop)\n")

    if args.open:
        import threading
        threading.Thread(target=_open_browser, args=(url, args.port), daemon=True).start()

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(target))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    return 0


def _open_browser(url: str, wait_port: int | None = None) -> None:
    import time
    import webbrowser
    if wait_port is not None:
        for _ in range(100):  # wait up to ~10s for the server to bind
            if port_in_use(wait_port):
                break
            time.sleep(0.1)
    try:
        webbrowser.open(url)
    except Exception:
        pass


if __name__ == "__main__":
    sys.exit(main())
