#!/usr/bin/env python3
"""
validate.py -- Redstrike framework linter (what CI runs). Stdlib only.

Checks across the repo:
  1. every skills/<skill>/review.md embeds a parseable JSON manifest with "artifacts"
  2. every skills/<skill> (except _contract) has SKILL.md + checklist.md + review.md
  3. a skill whose manifest declares a findings.json artifact has a verify.md
  4. every skills/_contract/*.schema.json is valid JSON
  5. every .claude/agents/*.md and .claude/skills/*/SKILL.md has frontmatter with name + description

Exit 0 = all good, 1 = problems (printed).
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FENCE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)
FM = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)

errors = []
checked = {"skills": 0, "manifests": 0, "schemas": 0, "agents": 0, "bindings": 0}


def err(msg):
    errors.append(msg)


def load_manifest(review_path):
    text = review_path.read_text(encoding="utf-8", errors="replace")
    for m in FENCE.finditer(text):
        try:
            obj = json.loads(m.group(1))
        except json.JSONDecodeError as e:
            return None, f"invalid JSON manifest: {e}"
        if isinstance(obj, dict) and "artifacts" in obj:
            return obj, None
    return None, "no JSON manifest with 'artifacts'"


def frontmatter_keys(md_path):
    text = md_path.read_text(encoding="utf-8", errors="replace")
    m = FM.match(text)
    if not m:
        return None
    keys = {}
    for line in m.group(1).splitlines():
        if ":" in line and not line.startswith((" ", "\t")):
            keys[line.split(":", 1)[0].strip()] = True
    return keys


def check_frontmatter(md_path, label):
    keys = frontmatter_keys(md_path)
    if keys is None:
        err(f"{label}: missing frontmatter")
        return
    for k in ("name", "description"):
        if k not in keys:
            err(f"{label}: frontmatter missing '{k}'")


def check_depth_substance(rmap):
    """Lint routing-map.json's `depth_substance` threshold shape (the DEPTH-SUBSTANCE BAR a zero-finding
    `attempted` clear must prove before the completion gate counts it covered). A malformed/incomplete block
    would silently disable or mis-tune the bar — "a gate the workflow can route around is not real" — so any
    drift FAILS. The block is OPTIONAL (absent => coverage.py uses its built-in default); when present it
    must be {default:{min_attempts,min_variants}, classes?:{<category-id>:{min_attempts,min_variants}}} with
    non-negative integers and class keys that are real category ids. Returns a list of error strings."""
    out = []
    cfg = rmap.get("depth_substance")
    if cfg is None:
        return out
    if not isinstance(cfg, dict):
        return ["routing-map.json: 'depth_substance' must be an object {default, classes?}"]

    def _check_entry(where, obj):
        if not isinstance(obj, dict):
            out.append(f"routing-map.json: depth_substance {where} must be an object with integer "
                       f"min_attempts / min_variants")
            return
        for k in ("min_attempts", "min_variants"):
            if k not in obj:
                out.append(f"routing-map.json: depth_substance {where} is missing '{k}'")
            elif not isinstance(obj[k], int) or isinstance(obj[k], bool) or obj[k] < 0:
                out.append(f"routing-map.json: depth_substance {where} '{k}' must be a non-negative integer")

    if "default" not in cfg:
        out.append("routing-map.json: depth_substance must declare a 'default' {min_attempts, min_variants}")
    else:
        _check_entry("default", cfg["default"])
    classes = cfg.get("classes", {})
    if not isinstance(classes, dict):
        out.append("routing-map.json: depth_substance.classes must be an object keyed by category id")
    else:
        valid_ids = {c.get("id") for c in rmap.get("categories", [])}
        for cid, obj in classes.items():
            if cid not in valid_ids:
                out.append(f"routing-map.json: depth_substance.classes has unknown category id '{cid}'")
            _check_entry(f"classes['{cid}']", obj)
    return out


# --- VRT (Vulnerability Rating Taxonomy) primitives -------------------------------------------------
# The pinned bug-bounty rating taxonomy (skills/bug-bounty/refs/vrt/) is the offline source of truth for
# valid VRT paths + baseline priorities. These helpers flatten it and validate a finding's OPTIONAL
# `vrt{}` block: (a) FABRICATION — the claimed path/id must resolve to a real taxonomy node; (b)
# INFLATION — the claimed priority may not be MORE severe (a lower P-number) than the node's baseline
# unless priority_basis=argued-elevation carries a non-empty priority_rationale. This is the QW primitive;
# the full crosswalk/resolver + a verify_completion HARD gate are larger follow-ups (out of scope here).
VRT_DIR = ROOT / "skills" / "bug-bounty" / "refs" / "vrt"
VRT_TAXONOMY_PATH = VRT_DIR / "vulnerability-rating-taxonomy.json"
# Taxonomy ids a scope.yaml `program.taxonomy` may reference (the pinned sets we ship; `none` = pentest).
KNOWN_TAXONOMIES = {"vrt", "none"}
_VRT_PRIO_RE = re.compile(r"^[Pp]?([1-5])$")


def _vrt_priority_int(value):
    """'P3' / '3' / 3 -> 3 ; None / '' / 'varies' -> None. Raises ValueError on anything else."""
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{value!r} is not a P1-P5 priority")
    if isinstance(value, int):
        if 1 <= value <= 5:
            return value
        raise ValueError(f"{value!r} is out of the P1-P5 range")
    s = str(value).strip()
    if not s or s.lower() == "varies":
        return None
    m = _VRT_PRIO_RE.match(s)
    if not m:
        raise ValueError(f"{value!r} is not a P1-P5 priority (or 'varies')")
    return int(m.group(1))


def _vrt_norm_path(p):
    """'A > B > C' -> ('a','b','c') (segment-wise stripped + lowercased; empty segments dropped)."""
    return tuple(seg.strip().lower() for seg in str(p).split(">") if seg.strip())


def flatten_vrt(taxonomy):
    """Flatten the pinned taxonomy's `content` tree to lookups:
         id_paths   { ('server_side_injection','content_spoofing','text_injection'): priority|None }
         name_paths { ('server-side injection','content spoofing','text injection'): priority|None }
         leaf_ids   { 'text_injection': [ (id_path_tuple, priority), ... ] }
       Records EVERY node (category/subcategory/variant), since the VRT assigns priorities at category and
       subcategory level too. `priority` is an int 1-5 or None ('varies')."""
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
        leaf_ids.setdefault(it[-1], []).append((it, prio))
        for c in node.get("children") or []:
            if isinstance(c, dict):
                walk(c, it, nt)

    for cat in (taxonomy or {}).get("content", []):
        if isinstance(cat, dict):
            walk(cat, (), ())
    return {"id_paths": id_paths, "name_paths": name_paths, "leaf_ids": leaf_ids}


def resolve_vrt(vrt, flat):
    """Resolve a finding's vrt{} to (node_key, baseline_priority), or (None, None) if it does not exist.
       Accepts a `>`-joined id-path OR name-path in `path`, optionally disambiguated by a leaf `id`."""
    path = vrt.get("path")
    vid = vrt.get("id")
    if path:
        key = _vrt_norm_path(path)
        if key in flat["id_paths"]:
            return key, flat["id_paths"][key]
        if key in flat["name_paths"]:
            return key, flat["name_paths"][key]
    if isinstance(vid, str) and vid.strip():
        cands = flat["leaf_ids"].get(vid.strip().lower())
        if cands:
            if path:
                pk = _vrt_norm_path(path)
                for it, prio in cands:
                    if it == pk or it[-len(pk):] == pk:
                        return it, prio
            return cands[0]  # resolved to a real node (first match if the id is ambiguous)
    return None, None


def vrt_finding_errors(finding, flat, where="finding"):
    """Validate a single finding's OPTIONAL vrt{} block against the pinned taxonomy. Returns error
       strings (empty = OK). A finding without a vrt{} block is unaffected (normal pentest finding)."""
    out = []
    vrt = finding.get("vrt") if isinstance(finding, dict) else None
    if not isinstance(vrt, dict):
        return out
    key, baseline = resolve_vrt(vrt, flat)
    if key is None:
        label = vrt.get("path") or vrt.get("id") or "<empty>"
        out.append(f"{where}: vrt {label!r} does NOT resolve to a node in the pinned taxonomy "
                   f"(fabricated VRT category)")
        return out
    basis = vrt.get("priority_basis", "baseline")
    if basis not in ("baseline", "argued-elevation", "argued-reduction"):
        out.append(f"{where}: vrt.priority_basis {basis!r} must be "
                   f"baseline/argued-elevation/argued-reduction")
    rationale = (vrt.get("priority_rationale") or "").strip()
    claimed = None
    try:
        claimed = _vrt_priority_int(vrt.get("priority"))
    except ValueError as e:
        out.append(f"{where}: vrt.priority {e}")
    # lower P-number = MORE severe; stronger-than-baseline means claimed < baseline.
    inflated = claimed is not None and baseline is not None and claimed < baseline
    if inflated:
        if basis != "argued-elevation":
            out.append(f"{where}: vrt.priority P{claimed} is STRONGER than the taxonomy baseline "
                       f"P{baseline} but priority_basis is {basis!r} — inflation; require "
                       f"'argued-elevation' + a priority_rationale")
        elif not rationale:
            out.append(f"{where}: vrt.priority P{claimed} elevated above baseline P{baseline} "
                       f"(argued-elevation) but priority_rationale is empty")
    elif basis in ("argued-elevation", "argued-reduction") and not rationale:
        out.append(f"{where}: vrt.priority_basis {basis!r} requires a non-empty priority_rationale")
    return out


def severity_basis_errors(finding, where="finding"):
    """Validate a single finding's OPTIONAL `severity_basis` axis-reconciliation field for pure
       field-INTERNAL consistency (mirrors vrt_finding_errors). validate.py is stdlib-only and does NOT
       compute CVSS, so it does NOT check the drift DIRECTION (declared-vs-computed) — that is
       verify_completion._cvss_drift_check's job; here we only enforce the field's own invariants. Returns
       error strings (empty = OK). A finding without `severity_basis` is unaffected (default = baseline)."""
    out = []
    if not isinstance(finding, dict):
        return out
    basis = finding.get("severity_basis")
    if basis is None:
        return out  # absent -> baseline, nothing to check
    if basis not in ("baseline", "demonstrated-vs-potential", "argued-elevation"):
        out.append(f"{where}: severity_basis {basis!r} must be "
                   f"baseline/demonstrated-vs-potential/argued-elevation")
        return out
    rationale = str(finding.get("severity_rationale") or "").strip()
    if basis == "argued-elevation" and not rationale:
        out.append(f"{where}: severity_basis 'argued-elevation' requires a non-empty severity_rationale "
                   f"(the argument for rating business severity above the CVSS arithmetic)")
    if basis == "demonstrated-vs-potential" and finding.get("potential_severity") is None:
        out.append(f"{where}: severity_basis 'demonstrated-vs-potential' requires potential_severity to be "
                   f"set (the vector's best-case the demonstrated severity is measured against)")
    return out


def scope_program_errors(program, known=None, where="scope.yaml"):
    """Validate a scope.yaml `program` mapping (a dict). Returns error strings. Absent program => an
       ordinary pentest engagement, nothing to check."""
    known = KNOWN_TAXONOMIES if known is None else known
    out = []
    if not isinstance(program, dict):
        return out
    plat = program.get("platform", "none")
    if plat not in ("bugcrowd", "hackerone", "none", None, ""):
        out.append(f"{where}: program.platform {plat!r} must be bugcrowd/hackerone/none")
    tax = program.get("taxonomy", "none")
    if tax not in known:
        out.append(f"{where}: program.taxonomy {tax!r} is not a known/pinned taxonomy "
                   f"({sorted(known)})")
    return out


def _parse_simple_block(yaml_text, block):
    """Stdlib extractor for a one-level mapping under a top-level `block:` key in SIMPLE YAML (our
       template's program block is flat `key: value` lines). validate.py is stdlib-only (no PyYAML), so
       this reads just enough to lint the template; the runtime gate parses scope.yaml with real YAML."""
    out = {}
    in_block = False
    indent = None
    for ln in yaml_text.splitlines():
        if re.match(rf"^{re.escape(block)}\s*:\s*(#.*)?$", ln):
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


def vrt_selftest(flat):
    """Deterministic VRT-validation self-check against the pinned taxonomy (mirrors the cvss self-test).
       Returns a list of failure strings; [] = all cases behaved as expected."""
    fails = []

    def expect(name, errs, want_fail):
        got_fail = bool(errs)
        if got_fail != want_fail:
            fails.append(f"vrt selftest [{name}]: expected {'FAIL' if want_fail else 'PASS'} but got "
                         + (f"FAIL {errs}" if got_fail else "PASS"))

    ssi_ti = "server_side_injection > content_spoofing > text_injection"   # baseline P5
    ssi_if = "server_side_injection > content_spoofing > iframe_injection"  # baseline P3
    # real path at baseline -> PASS (by id-path and by display-name path)
    expect("real-baseline", vrt_finding_errors(
        {"vrt": {"path": ssi_ti, "id": "text_injection", "priority": "P5", "priority_basis": "baseline"}}, flat), False)
    expect("real-name-path", vrt_finding_errors(
        {"vrt": {"path": "Server-Side Injection > Content Spoofing > Text Injection", "priority": "P5"}}, flat), False)
    # the real incident: a fabricated (non-existent) VRT category -> FAIL
    expect("fabricated", vrt_finding_errors(
        {"vrt": {"path": "Broken Access Control — Improper Authorization / Server-Side", "priority": "P3"}}, flat), True)
    # inflation: P3 on a P5-baseline class with no argued basis -> FAIL
    expect("inflation-nobasis", vrt_finding_errors(
        {"vrt": {"path": ssi_ti, "priority": "P3", "priority_basis": "baseline"}}, flat), True)
    # inflation declared argued-elevation but NO rationale -> FAIL
    expect("inflation-norationale", vrt_finding_errors(
        {"vrt": {"path": ssi_ti, "priority": "P3", "priority_basis": "argued-elevation"}}, flat), True)
    # inflation argued-elevation WITH rationale -> PASS (the legitimate RS-2026-062 shape)
    expect("inflation-argued-ok", vrt_finding_errors(
        {"vrt": {"path": ssi_ti, "priority": "P3", "priority_basis": "argued-elevation",
                 "priority_rationale": "demonstrated cross-user nickname spoofing, not plain text injection"}}, flat), False)
    # reduction (weaker than baseline) with argued-reduction + rationale -> PASS
    expect("reduction-ok", vrt_finding_errors(
        {"vrt": {"path": ssi_if, "priority": "P5", "priority_basis": "argued-reduction",
                 "priority_rationale": "no sensitive action is framed"}}, flat), False)
    # a bad priority token -> FAIL
    expect("bad-priority", vrt_finding_errors({"vrt": {"path": ssi_ti, "priority": "P9"}}, flat), True)
    # a normal finding with NO vrt block -> PASS (unaffected)
    expect("no-vrt", vrt_finding_errors({"id": "RS-2026-001", "severity": "low"}, flat), False)
    # scope program.taxonomy checks
    expect("scope-vrt-ok", scope_program_errors({"platform": "bugcrowd", "taxonomy": "vrt"}), False)
    expect("scope-none-ok", scope_program_errors({"platform": "none", "taxonomy": "none"}), False)
    expect("scope-bad-tax", scope_program_errors({"platform": "bugcrowd", "taxonomy": "madeup"}), True)
    expect("scope-bad-platform", scope_program_errors({"platform": "nope", "taxonomy": "none"}), True)
    return fails


def severity_basis_selftest():
    """Deterministic severity_basis-validation self-check (mirrors vrt_selftest). Pure field-internal
       consistency only (no CVSS). Returns a list of failure strings; [] = all cases behaved as expected."""
    fails = []

    def expect(name, errs, want_fail):
        got_fail = bool(errs)
        if got_fail != want_fail:
            fails.append(f"severity_basis selftest [{name}]: expected {'FAIL' if want_fail else 'PASS'} "
                         + (f"but got FAIL {errs}" if got_fail else "but got PASS"))

    # absent -> baseline, unaffected (an ordinary finding)
    expect("absent", severity_basis_errors({"id": "RS-2026-001", "severity": "high"}), False)
    # explicit baseline -> PASS
    expect("baseline", severity_basis_errors({"severity_basis": "baseline"}), False)
    # an unknown basis value -> FAIL
    expect("bad-value", severity_basis_errors({"severity_basis": "made-up"}), True)
    # argued-elevation WITH a rationale -> PASS (the shopware RS-2026-* inflation shape)
    expect("argued-ok", severity_basis_errors(
        {"severity_basis": "argued-elevation", "severity_rationale": "cross-tenant data integrity impact"}), False)
    # argued-elevation with NO rationale -> FAIL
    expect("argued-norationale", severity_basis_errors({"severity_basis": "argued-elevation"}), True)
    # argued-elevation with a blank/whitespace rationale -> FAIL
    expect("argued-blank", severity_basis_errors(
        {"severity_basis": "argued-elevation", "severity_rationale": "   "}), True)
    # demonstrated-vs-potential WITH potential_severity set -> PASS
    expect("dvp-ok", severity_basis_errors(
        {"severity_basis": "demonstrated-vs-potential", "severity": "low", "potential_severity": "high"}), False)
    # demonstrated-vs-potential WITHOUT potential_severity -> FAIL
    expect("dvp-nopotential", severity_basis_errors(
        {"severity_basis": "demonstrated-vs-potential", "severity": "low"}), True)
    return fails


def check_vrt():
    """23 — pinned VRT taxonomy + finding-vrt fabrication/inflation + scope program.taxonomy (the QW
       reporting-VRT primitives; wired here like the cvss/coverage self-tests)."""
    checked["vrt"] = 1
    if not VRT_TAXONOMY_PATH.is_file():
        err("skills/bug-bounty/refs/vrt/vulnerability-rating-taxonomy.json missing (the pinned VRT taxonomy)")
        return
    try:
        tax = json.loads(VRT_TAXONOMY_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        err(f"vulnerability-rating-taxonomy.json: invalid JSON: {e}")
        return
    meta = tax.get("_meta") if isinstance(tax, dict) else None
    if not isinstance(meta, dict):
        err("vulnerability-rating-taxonomy.json: missing provenance `_meta` block")
    else:
        for req in ("upstream_source", "upstream_ref", "upstream_version", "fetched_at", "refresh_policy"):
            if not meta.get(req):
                err(f"vulnerability-rating-taxonomy.json: _meta is missing provenance key '{req}'")
    flat = flatten_vrt(tax if isinstance(tax, dict) else {})
    if not flat["id_paths"]:
        err("vulnerability-rating-taxonomy.json: no paths parsed from `content` (empty/malformed taxonomy)")
        return
    if not any(p is not None for p in flat["id_paths"].values()):
        err("vulnerability-rating-taxonomy.json: no node carries a baseline priority "
            "(a taxonomy with no priorities cannot gate inflation)")
    anchor = ("server_side_injection", "content_spoofing", "text_injection")
    if flat["id_paths"].get(anchor) != 5:
        err("vulnerability-rating-taxonomy.json: anchor path "
            "server_side_injection>content_spoofing>text_injection must be baseline P5 "
            f"(got {flat['id_paths'].get(anchor)!r}) — pinned-taxonomy drift")
    for f in vrt_selftest(flat):
        err(f)
    # severity_basis axis-reconciliation field self-check (L-C) — the demonstrated-severity-vs-CVSS
    # reconciliation field validated alongside the VRT headline axis; wired here like vrt_selftest.
    checked["severity_basis"] = 1
    for f in severity_basis_selftest():
        err(f)
    # (c) the TEMPLATE scope.yaml program.taxonomy must reference a known/pinned taxonomy
    tmpl = ROOT / "engagements" / "_template" / "scope.yaml"
    if tmpl.is_file():
        prog = _parse_simple_block(tmpl.read_text(encoding="utf-8", errors="replace"), "program")
        if not prog:
            err("engagements/_template/scope.yaml: missing the structured `program:` block")
        else:
            for e in scope_program_errors(prog, where="engagements/_template/scope.yaml"):
                err(e)
    # (d) the CWE/finding-class -> VRT crosswalk: it must parse, carry provenance, and EVERY target path
    # must resolve to a real node in the pinned taxonomy (a crosswalk entry pointing at a non-existent VRT
    # node is a HARD failure — the resolver would hand the submission generator a fabricated path).
    check_vrt_crosswalk(flat)


def check_vrt_crosswalk(flat):
    """Validate skills/bug-bounty/refs/vrt/vrt_crosswalk.json: parse + provenance + every `path` resolves."""
    xw_path = VRT_DIR / "vrt_crosswalk.json"
    if not xw_path.is_file():
        err("skills/bug-bounty/refs/vrt/vrt_crosswalk.json missing (the CWE/class -> VRT crosswalk)")
        return
    try:
        xw = json.loads(xw_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        err(f"vrt_crosswalk.json: invalid JSON: {e}")
        return
    if not isinstance(xw, dict):
        err("vrt_crosswalk.json: top-level must be an object")
        return
    if not isinstance(xw.get("_meta"), dict):
        err("vrt_crosswalk.json: missing provenance `_meta` block")
    n_targets = 0
    for section in ("cwe", "class"):
        entries = xw.get(section)
        if entries is None:
            continue
        if not isinstance(entries, dict):
            err(f"vrt_crosswalk.json: `{section}` must be an object")
            continue
        for key, entry in entries.items():
            if isinstance(entry, dict) and isinstance(entry.get("candidates"), list):
                cands = [c for c in entry["candidates"] if isinstance(c, dict)]
            elif isinstance(entry, dict) and entry.get("path"):
                cands = [entry]
            else:
                err(f"vrt_crosswalk.json: {section}.{key} has no `path` or `candidates`")
                continue
            if not cands:
                err(f"vrt_crosswalk.json: {section}.{key} has an empty candidate list")
            for cand in cands:
                n_targets += 1
                p = cand.get("path")
                norm = _vrt_norm_path(p) if p else ()
                if not p or (norm not in flat["id_paths"] and norm not in flat["name_paths"]):
                    err(f"vrt_crosswalk.json: {section}.{key} target path {p!r} does NOT resolve in the "
                        f"pinned taxonomy (crosswalk points at a non-existent VRT node)")
                elif cand.get("id") and str(cand["id"]).strip().lower() != norm[-1]:
                    err(f"vrt_crosswalk.json: {section}.{key} id {cand['id']!r} is not the leaf of path "
                        f"{p!r} (expected {norm[-1]!r})")
    checked["vrt_crosswalk"] = n_targets


# 1 + 2 + 3 — skills
skills_dir = ROOT / "skills"
for sk in sorted(p for p in skills_dir.iterdir() if p.is_dir() and p.name != "_contract"):
    checked["skills"] += 1
    for req in ("SKILL.md", "checklist.md", "review.md"):
        if not (sk / req).is_file():
            err(f"{sk.name}: missing {req}")
    review = sk / "review.md"
    if review.is_file():
        checked["manifests"] += 1
        obj, problem = load_manifest(review)
        if problem:
            err(f"{sk.name}/review.md: {problem}")
        else:
            arts = obj.get("artifacts", [])
            if any(a.get("path") == "findings.json" for a in arts):
                if not (sk / "verify.md").is_file():
                    err(f"{sk.name}: manifest declares findings.json but has no verify.md")
            # a `schema` ref must resolve to a real _contract schema, else the runtime
            # gate (verify_completion.check_artifact) SILENTLY skips validation for it.
            for a in arts:
                ref = a.get("schema")
                if not ref:
                    continue
                checked["schema_refs"] = checked.get("schema_refs", 0) + 1
                aid = a.get("id", a.get("path", "?"))
                if not (isinstance(ref, str) and ref.startswith("skills/_contract/")
                        and ref.endswith(".schema.json")):
                    err(f"{sk.name}/review.md: artifact '{aid}' schema ref '{ref}' "
                        f"is not a skills/_contract/*.schema.json path")
                elif not (ROOT / ref).is_file():
                    err(f"{sk.name}/review.md: artifact '{aid}' references missing schema '{ref}'")

# 4 — schemas
for schema in sorted((skills_dir / "_contract").glob("*.schema.json")):
    checked["schemas"] += 1
    try:
        json.loads(schema.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        err(f"{schema.name}: invalid JSON: {e}")

# 4b — schema versioning: finding / attack_chain / *_context artifacts must declare a `version` field so
# their shape can evolve without silently breaking consumers (extends the map_version pattern). A drift
# guard: if the field is dropped, this fails.
for scm in sorted((skills_dir / "_contract").glob("*_context.schema.json")) + [
        skills_dir / "_contract" / "attack_chain.schema.json"]:
    if not scm.is_file():
        continue
    try:
        d = json.loads(scm.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        continue  # already reported by check 4
    checked["schema_version"] = checked.get("schema_version", 0) + 1
    if "version" not in (d.get("properties") or {}):
        err(f"{scm.name}: schema must declare a root 'version' property (schema-versioning drift)")
fsp = skills_dir / "_contract" / "finding.schema.json"
if fsp.is_file():
    try:
        fd = json.loads(fsp.read_text(encoding="utf-8"))
        checked["schema_version"] = checked.get("schema_version", 0) + 1
        if "version" not in ((fd.get("$defs", {}).get("finding", {}) or {}).get("properties") or {}):
            err("finding.schema.json: $defs/finding must declare a 'version' property (schema-versioning drift)")
    except json.JSONDecodeError:
        pass

# 5 — .claude agents + skill bindings
agents_dir = ROOT / ".claude" / "agents"
if agents_dir.is_dir():
    for a in sorted(agents_dir.glob("*.md")):
        checked["agents"] += 1
        check_frontmatter(a, f".claude/agents/{a.name}")

cskills = ROOT / ".claude" / "skills"
if cskills.is_dir():
    for sd in sorted(p for p in cskills.iterdir() if p.is_dir()):
        checked["bindings"] += 1
        skill_md = sd / "SKILL.md"
        if not skill_md.is_file():
            err(f".claude/skills/{sd.name}: missing SKILL.md")
        else:
            check_frontmatter(skill_md, f".claude/skills/{sd.name}/SKILL.md")

# 6 — cvss calculator self-check (deterministic scoring reporting/verify rely on)
sys.path.insert(0, str(ROOT / "scripts"))
try:
    import cvss as _cvss
    for vec, want_score, want_rating in _cvss._SELFTEST:
        checked["cvss"] = checked.get("cvss", 0) + 1
        try:
            score, rating, _ = _cvss.score_vector(vec)
        except Exception as e:  # noqa: BLE001
            err(f"cvss: {vec} raised {e}")
            continue
        if abs(score - want_score) > 1e-9 or rating != want_rating:
            err(f"cvss: {vec} -> {score} {rating}, expected {want_score} {want_rating}")
except ImportError as e:
    err(f"cvss: cannot import scripts/cvss.py: {e}")

# 6b — vrt resolver self-check (the deterministic CWE/class -> VRT crosswalk + resolver the bug-bounty
# submission generator relies on). Wired like the cvss self-test so CI runs it on every push.
try:
    import vrt as _vrt
    checked["vrt_selftest"] = 1
    _vrt.selftest()
except BaseException as e:  # noqa: BLE001 — selftest asserts; a data-load failure must surface here too
    err(f"vrt.py selftest failed: {e}")

# 7 — routing map covers every executor exactly once (so a new class can't silently become an orphan)
map_path = ROOT / "skills" / "_contract" / "routing-map.json"
if not map_path.is_file():
    err("skills/_contract/routing-map.json missing")
else:
    try:
        rmap = json.loads(map_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        rmap = None
        err(f"routing-map.json: invalid JSON: {e}")
    if rmap:
        checked["routing"] = 1
        executors = {p.name for p in skills_dir.iterdir()
                     if p.is_dir() and (p / "verify.md").is_file()}
        mapped = [a for c in rmap.get("categories", []) for a in c.get("agents", [])]
        mapped_set = set(mapped)
        for miss in sorted(executors - mapped_set):
            err(f"routing-map.json: executor '{miss}' is routed by no category (orphan — wire a trigger)")
        for extra in sorted(mapped_set - executors):
            err(f"routing-map.json: agent '{extra}' has no skills/{extra}/ dir")
        if len(mapped) != len(mapped_set):
            dups = sorted({a for a in mapped if mapped.count(a) > 1})
            err(f"routing-map.json: executor(s) mapped to >1 category: {', '.join(dups)}")
        vocab = set(rmap.get("signals", {}))
        for c in rmap.get("categories", []):
            for t in c.get("triggers", []):
                if t not in vocab:
                    err(f"routing-map.json: category '{c['id']}' uses undefined signal '{t}'")
            if not c.get("baseline") and c.get("phase") != "capability" and not c.get("skip_reason"):
                err(f"routing-map.json: category '{c['id']}' is non-baseline but has no skip_reason")

        # 7b — signal provenance: every category trigger signal must have a DECLARED emitter in
        # signal_sources, else it is a STARVED EXECUTOR — nothing emits the signal, so the category
        # silently skips itself on a signal-driven coverage plan (the subdomain-takeover/asset:dangling-dns
        # leak). Producers must be a real recon-feeder skills/ dir or a special (operator/post-ex/pipeline).
        sources = {k: v for k, v in rmap.get("signal_sources", {}).items() if k != "_comment"}
        SPECIAL_PRODUCERS = {"operator", "post-exploitation", "pipeline"}
        skill_dirs = {p.name for p in (ROOT / "skills").iterdir() if p.is_dir()}
        for c in rmap.get("categories", []):
            if c.get("phase") == "capability":
                continue
            for t in c.get("triggers", []):
                if not sources.get(t):
                    err(f"routing-map.json: category '{c['id']}' trigger '{t}' has NO producer in "
                        f"signal_sources — starved executor (nothing emits '{t}', so it silently skips)")
        for sig, producers in sources.items():
            if sig not in vocab:
                err(f"routing-map.json: signal_sources has unknown signal '{sig}' (not in the vocab)")
            if not isinstance(producers, list) or not producers:
                err(f"routing-map.json: signal_sources['{sig}'] must be a non-empty producer list")
                continue
            for p in producers:
                if p not in SPECIAL_PRODUCERS and p not in skill_dirs:
                    err(f"routing-map.json: signal_sources['{sig}'] names unknown producer '{p}' "
                        f"(not a skills/ feeder, not a special {sorted(SPECIAL_PRODUCERS)})")
        for sig in sorted(vocab - set(sources)):
            err(f"routing-map.json: signal '{sig}' is in the vocab but has no signal_sources producer "
                f"(dead signal — give it a producer or remove it)")
        checked["signal_provenance"] = len(sources)

        # 7c — signal-vocabulary schema sync: skills/_contract/signals.schema.json enumerates the SAME
        # closed vocabulary routing-map.json declares, so coordination artifacts (the re-convergence inbox,
        # coverage_ledger.signals_used, the signals feeder) can be validated against one source. Any drift in
        # either direction is a FAIL — a signal in the vocab but not the schema can't be validated, and a
        # signal in the schema but not the vocab routes to nothing (the sink:dom-backlink leak shape).
        sig_schema_path = ROOT / "skills" / "_contract" / "signals.schema.json"
        if not sig_schema_path.is_file():
            err("skills/_contract/signals.schema.json missing (the signal-vocabulary schema)")
        else:
            try:
                sig_schema = json.loads(sig_schema_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as e:
                sig_schema = None
                err(f"signals.schema.json: invalid JSON: {e}")
            if sig_schema is not None:
                checked["signal_vocab"] = 1
                schema_vocab = set((sig_schema.get("$defs", {}).get("signal", {}) or {}).get("enum", []) or [])
                if not schema_vocab:
                    err("signals.schema.json: $defs/signal/enum is empty or missing (no vocabulary)")
                for extra in sorted(schema_vocab - vocab):
                    err(f"signals.schema.json: enum has '{extra}' which routing-map.json does not declare "
                        f"(a signal that routes to nothing)")
                for missing in sorted(vocab - schema_vocab):
                    err(f"signals.schema.json: enum is MISSING '{missing}' from the routing-map vocab "
                        f"(it could not be validated at ingest)")

        # 7d — depth-substance threshold shape (the DEPTH-SUBSTANCE BAR config; see check_depth_substance)
        for _dse in check_depth_substance(rmap):
            err(_dse)
        checked["depth_substance"] = checked.get("depth_substance", 0) + 1

# 8 — coverage.py routing/ledger self-test
try:
    import importlib.util
    _cp = ROOT / "scripts" / "coverage.py"
    _spec = importlib.util.spec_from_file_location("rs_coverage_lint", _cp)
    _cov = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_cov)
    import io
    import contextlib
    with contextlib.redirect_stdout(io.StringIO()):
        _cov.selftest()
    checked["coverage"] = 1
except BaseException as e:  # noqa: BLE001 — selftest may sys.exit on a bad map
    err(f"coverage.py selftest failed: {e}")

# 8b — sqli_union self-test (UNION column-count derivation must stay open-ended; Juice Shop 10-col regression)
sqliu = ROOT / "scripts" / "sqli_union.py"
if sqliu.is_file():
    try:
        import importlib.util
        _sspec = importlib.util.spec_from_file_location("rs_sqliunion_lint", sqliu)
        _su = importlib.util.module_from_spec(_sspec)
        _sspec.loader.exec_module(_su)
        import io
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            _su.selftest()
        checked["sqli_union"] = 1
    except BaseException as e:  # noqa: BLE001
        err(f"sqli_union.py selftest failed: {e}")

# 8b2 — jwt_placements self-test (forged token must ride a header AND a cookie; no header-only clean)
jwtp = ROOT / "scripts" / "jwt_placements.py"
if jwtp.is_file():
    try:
        import importlib.util
        _jspec = importlib.util.spec_from_file_location("rs_jwtplacements_lint", jwtp)
        _jp = importlib.util.module_from_spec(_jspec)
        sys.modules["rs_jwtplacements_lint"] = _jp  # dataclass needs its module registered
        _jspec.loader.exec_module(_jp)
        import io
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            _jp.selftest()
        checked["jwt_placements"] = 1
    except BaseException as e:  # noqa: BLE001
        err(f"jwt_placements.py selftest failed: {e}")

# 8b3 — dangling_dns self-test (recon emits asset:dangling-dns so subdomain-takeover isn't skipped)
ddp = ROOT / "scripts" / "dangling_dns.py"
if ddp.is_file():
    try:
        import importlib.util
        _ddspec = importlib.util.spec_from_file_location("rs_danglingdns_lint", ddp)
        _dd = importlib.util.module_from_spec(_ddspec)
        _ddspec.loader.exec_module(_dd)
        import io
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            _dd.selftest()
        checked["dangling_dns"] = 1
    except BaseException as e:  # noqa: BLE001
        err(f"dangling_dns.py selftest failed: {e}")

# 8c — escalation ladder self-test (empty-class escalation decisions stay deterministic)
escp = ROOT / "scripts" / "escalation.py"
if escp.is_file():
    try:
        import importlib.util
        _espec = importlib.util.spec_from_file_location("rs_escalation_lint", escp)
        _esc = importlib.util.module_from_spec(_espec)
        _espec.loader.exec_module(_esc)
        import io
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            _esc.selftest()
        checked["escalation"] = 1
    except BaseException as e:  # noqa: BLE001
        err(f"escalation.py selftest failed: {e}")

# 8e — surface-coverage ledger self-test (route/validate/plan stay deterministic)
surfp = ROOT / "scripts" / "surface.py"
if surfp.is_file():
    try:
        import importlib.util
        _sfspec = importlib.util.spec_from_file_location("rs_surface_lint", surfp)
        _sf = importlib.util.module_from_spec(_sfspec)
        sys.modules["rs_surface_lint"] = _sf
        _sfspec.loader.exec_module(_sf)
        import io
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            _sf.selftest()
        checked["surface"] = 1
    except BaseException as e:  # noqa: BLE001
        err(f"surface.py selftest failed: {e}")

# 8f — reconverge self-test (finding->recon re-convergence fixpoint stays deterministic + terminates)
recp = ROOT / "scripts" / "reconverge.py"
if recp.is_file():
    try:
        import importlib.util
        _rcspec = importlib.util.spec_from_file_location("rs_reconverge_lint", recp)
        _rc = importlib.util.module_from_spec(_rcspec)
        sys.modules["rs_reconverge_lint"] = _rc
        _rcspec.loader.exec_module(_rc)
        import io
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            _rc.selftest()
        checked["reconverge"] = 1
    except BaseException as e:  # noqa: BLE001
        err(f"reconverge.py selftest failed: {e}")

# 8d — recall_audit self-test (the "what did we miss?" altitude stays deterministic)
raup = ROOT / "scripts" / "recall_audit.py"
if raup.is_file():
    try:
        import importlib.util
        _rspec = importlib.util.spec_from_file_location("rs_recallaudit_lint", raup)
        _ra = importlib.util.module_from_spec(_rspec)
        sys.modules["rs_recallaudit_lint"] = _ra
        _rspec.loader.exec_module(_ra)
        import io
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            _ra.selftest()
        checked["recall_audit"] = 1
    except BaseException as e:  # noqa: BLE001
        err(f"recall_audit.py selftest failed: {e}")

# 8f2 — reproduce self-test (the MEASURED per-finding reproducibility harness that PRODUCES the
# reliability_runs/reliability_hits evidence_score consumes: hit-counting by the finding's own criterion,
# the bounded-K + rate-limit loop, and the hard refusal to auto-repeat non-idempotent/destructive probes).
repp = ROOT / "scripts" / "reproduce.py"
if repp.is_file():
    try:
        import importlib.util
        _rpspec = importlib.util.spec_from_file_location("rs_reproduce_lint", repp)
        _rp = importlib.util.module_from_spec(_rpspec)
        sys.modules["rs_reproduce_lint"] = _rp  # dataclasses need the module registered
        _rpspec.loader.exec_module(_rp)
        import io
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            _rp.selftest()
        # the harness threshold must mirror the scorer's race/timing flag threshold (no drift)
        if _rp.RELIABILITY_MIN != 0.8:
            err(f"reproduce.py: RELIABILITY_MIN {_rp.RELIABILITY_MIN} must mirror evidence_score's 0.8")
        checked["reproduce"] = 1
    except BaseException as e:  # noqa: BLE001
        err(f"reproduce.py selftest failed: {e}")

# 8g — dedup self-test (deterministic cross-agent de-duplication: canonical key + merge selection)
ddup = ROOT / "scripts" / "dedup.py"
if ddup.is_file():
    try:
        import importlib.util
        _dspec = importlib.util.spec_from_file_location("rs_dedup_lint", ddup)
        _ded = importlib.util.module_from_spec(_dspec)
        sys.modules["rs_dedup_lint"] = _ded
        _dspec.loader.exec_module(_ded)
        import io
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            _ded.selftest()
        checked["dedup"] = 1
    except BaseException as e:  # noqa: BLE001
        err(f"dedup.py selftest failed: {e}")

# 8h — chain_validate self-test (attack-chain integrity: step->accepted finding + composite flag)
chvp = ROOT / "scripts" / "chain_validate.py"
if chvp.is_file():
    try:
        import importlib.util
        _chspec = importlib.util.spec_from_file_location("rs_chainvalidate_lint", chvp)
        _chv = importlib.util.module_from_spec(_chspec)
        sys.modules["rs_chainvalidate_lint"] = _chv
        _chspec.loader.exec_module(_chv)
        import io
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            _chv.selftest()
        checked["chain_validate"] = 1
    except BaseException as e:  # noqa: BLE001
        err(f"chain_validate.py selftest failed: {e}")

# 8i — structvalidate self-test (the shared stdlib structural validator console.py serves artifacts
# through; keeps strict/lenient + the js-analysis drift-catch deterministic)
svp = ROOT / "scripts" / "structvalidate.py"
if svp.is_file():
    try:
        import importlib.util
        _svspec = importlib.util.spec_from_file_location("rs_structvalidate_lint", svp)
        _sv = importlib.util.module_from_spec(_svspec)
        sys.modules["rs_structvalidate_lint"] = _sv
        _svspec.loader.exec_module(_sv)
        import io
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            _sv.selftest()
        checked["structvalidate"] = 1
    except BaseException as e:  # noqa: BLE001
        err(f"structvalidate.py selftest failed: {e}")

# 9 — cve_prioritize self-test (KEV/EPSS/reachability/CVSS ranking logic)
cvep = ROOT / "scripts" / "cve_prioritize.py"
if cvep.is_file():
    try:
        import importlib.util
        _cspec = importlib.util.spec_from_file_location("rs_cveprio_lint", cvep)
        _cve = importlib.util.module_from_spec(_cspec)
        _cspec.loader.exec_module(_cve)
        import io
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            _cve.selftest()
        checked["cve_prioritize"] = 1
    except BaseException as e:  # noqa: BLE001
        err(f"cve_prioritize.py selftest failed: {e}")

# 10 — recall-benchmark self-test (target specs valid + each category_map in sync with the routing map).
# This is the benchmark's CI footprint: the recall RUN is an operator workflow (needs a live target), but
# the harness + specs + mappings are guarded here. See benchmark/README.md.
bench_py = ROOT / "scripts" / "benchmark.py"
if bench_py.is_file():
    try:
        import importlib.util
        _bspec = importlib.util.spec_from_file_location("rs_benchmark_lint", bench_py)
        _bench = importlib.util.module_from_spec(_bspec)
        _bspec.loader.exec_module(_bench)
        import io
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            _bench.selftest()
        checked["benchmark"] = 1
    except BaseException as e:  # noqa: BLE001 — selftest asserts / may sys.exit on a bad spec
        err(f"benchmark.py selftest failed: {e}")

# 11 — SKILL.md section-presence lint: every skill carries the load-bearing sections, so the
# interview/goal/phases/safety + steps-or-orchestration spine can't silently rot out of a SKILL.md.
_REQUIRED_SECTIONS = ("## Interview", "## Goal", "## Phases", "## Safety")
_skill_md_dirs = [p for p in sorted(skills_dir.iterdir())
                  if p.is_dir() and p.name != "_contract" and (p / "SKILL.md").is_file()]
for sk in _skill_md_dirs:
    text = (sk / "SKILL.md").read_text(encoding="utf-8", errors="replace")
    checked["skill_sections"] = checked.get("skill_sections", 0) + 1
    for h in _REQUIRED_SECTIONS:
        if h not in text:
            err(f"{sk.name}/SKILL.md: missing required section '{h}'")
    if "## Steps" not in text and "## Orchestration" not in text:
        err(f"{sk.name}/SKILL.md: missing a '## Steps' or '## Orchestration' section")

# 12 — findings-producer lint: a skill with a verify.md is a findings producer, so its contract wiring
# (RoE gate + verify-base inheritance + FP gauntlet + the full 4-verdict template) must be present.
for sk in sorted(p for p in skills_dir.iterdir() if p.is_dir() and p.name != "_contract"):
    verify_md = sk / "verify.md"
    if not verify_md.is_file():
        continue
    checked["producer_lint"] = checked.get("producer_lint", 0) + 1
    skill_text = (sk / "SKILL.md").read_text(encoding="utf-8", errors="replace") if (sk / "SKILL.md").is_file() else ""
    verify_text = verify_md.read_text(encoding="utf-8", errors="replace")
    if "roe-gate.md" not in skill_text:
        err(f"{sk.name}/SKILL.md: findings producer must reference roe-gate.md")
    if "verify-base.md" not in verify_text:
        err(f"{sk.name}/verify.md: must reference verify-base.md")
    if not re.search(r"(?mi)^#+ .*gauntlet", verify_text):
        err(f"{sk.name}/verify.md: missing a false-positive gauntlet heading")
    for verdict in ("accepted", "blocked", "rejected", "needs-evidence"):
        if verdict not in verify_text:
            err(f"{sk.name}/verify.md: verdict template is missing the '{verdict}' verdict")
    # reviewer rigor: the CVSS step must tell the reviewer to COMPUTE Medium+ vectors with scripts/cvss.py
    # (don't hand-assert the score). A drift guard for the P2-4 sweep.
    if "scripts/cvss.py" not in verify_text:
        err(f"{sk.name}/verify.md: CVSS step must reference scripts/cvss.py (compute Medium+ vectors)")

# 13 — binding symmetry: every executor's verify.md must have a matching .claude/agents/<x>-verify.md
# reviewer, and every <x>-verify reviewer must have a matching executor — no orphan on either side.
_exec_names = {p.name for p in skills_dir.iterdir() if p.is_dir() and (p / "verify.md").is_file()}
_agent_verify = {p.name[:-len("-verify.md")] for p in agents_dir.glob("*-verify.md")} if agents_dir.is_dir() else set()
# cross-cutting reviewers that are deliberately NOT 1:1 with an executor (one reviewer
# spanning many classes, e.g. the cross-model adversarial second-verifier) — exempt from
# the executor<->reviewer symmetry check AND from the per-class reviewer count (#15).
_CROSS_CUTTING_VERIFIERS = {"adversarial"}
_agent_verify -= _CROSS_CUTTING_VERIFIERS
checked["verify_bindings"] = len(_exec_names)
for orphan in sorted(_exec_names - _agent_verify):
    err(f"binding: skills/{orphan}/verify.md has no matching .claude/agents/{orphan}-verify.md")
for orphan in sorted(_agent_verify - _exec_names):
    err(f"binding: .claude/agents/{orphan}-verify.md has no matching skills/{orphan}/verify.md")

# 14 — findings-artifact schema check: any manifest artifact that is a findings file must declare the
# finding schema, else verify_completion.check_artifact silently skips schema validation for it.
for sk in sorted(p for p in skills_dir.iterdir() if p.is_dir() and p.name != "_contract"):
    review = sk / "review.md"
    if not review.is_file():
        continue
    obj, problem = load_manifest(review)
    if problem or not obj:
        continue  # manifest-level problems are already reported by check #1
    for a in obj.get("artifacts", []):
        path = a.get("path")
        if path == "findings.json":
            checked["findings_schema"] = checked.get("findings_schema", 0) + 1
            if a.get("schema") != "skills/_contract/finding.schema.json":
                err(f"{sk.name}/review.md: findings.json artifact must declare "
                    f"schema: skills/_contract/finding.schema.json (has {a.get('schema')!r})")
        elif path == "findings_consolidated.json":
            checked["findings_schema"] = checked.get("findings_schema", 0) + 1
            if not a.get("schema"):
                err(f"{sk.name}/review.md: findings_consolidated.json artifact must declare a schema ref")

# 15 — count/drift gate: the README's advertised numbers must match the real repo, computed here, so a
# new skill/executor/reviewer can't land while the badges + body quietly drift out of date.
_n_skills = len(_skill_md_dirs)
_n_executors = sum(1 for p in _skill_md_dirs if (p / "verify.md").is_file())
_n_reviewers = len([p for p in agents_dir.glob("*-verify.md")
                    if p.name[:-len("-verify.md")] not in _CROSS_CUTTING_VERIFIERS]) if agents_dir.is_dir() else 0
_n_review_only = _n_skills - _n_executors
_readme = ROOT / "README.md"
if not _readme.is_file():
    err("README.md missing — cannot run the count/drift gate")
else:
    _rtext = _readme.read_text(encoding="utf-8", errors="replace")
    checked["counts"] = 1
    _count_checks = [
        ("Skills badge", r"badge/Skills-(\d+)-", _n_skills),
        ("Vuln Agents badge", r"badge/Vuln%20Agents-(\d+)-", _n_executors),
        ("Reviewer Agents badge", r"badge/Reviewer%20Agents-(\d+)-", _n_reviewers),
        ("body skill count", r"\*\*(\d+) skills\*\*", _n_skills),
        ("body executor count", r"\*\*(\d+) findings-producing executors\*\*", _n_executors),
        ("body reviewer count", r"\((\d+) `\*-verify` agents\)", _n_reviewers),
        ("body review-only count", r"\*\*(\d+) review-only\*\*", _n_review_only),
    ]
    for _label, _pat, _expected in _count_checks:
        _m = re.search(_pat, _rtext)
        if not _m:
            err(f"README count gate: can't find the '{_label}' number (pattern {_pat!r})")
        elif int(_m.group(1)) != _expected:
            err(f"README count gate: {_label} says {_m.group(1)} but the repo has {_expected}")

# 16 — reviewer-rigor lint: every `*-verify` agent's load list must include the shared counterevidence +
# severity-calibration rubric files, so the reviewer loads them up front (not just transitively). Drift
# guard for the P2-4 sweep.
if agents_dir.is_dir():
    for a in sorted(agents_dir.glob("*-verify.md")):
        checked["reviewer_rigor"] = checked.get("reviewer_rigor", 0) + 1
        atext = a.read_text(encoding="utf-8", errors="replace")
        for ref in ("counterevidence.md", "severity-calibration.md"):
            if ref not in atext:
                err(f".claude/agents/{a.name}: reviewer must load skills/_contract/{ref}")

# 17 — strategist / hunt_plan registration: the Tier-3 `strategist` planning skill is review-only (it
# emits hunt_plan.json, NOT findings, so it must NOT grow a verify.md), and its hunt_plan.schema.json
# must be a valid, versioned schema whose ranking-only INVARIANT holds in the shape itself — no `skipped`
# queue-state (only coverage.py may skip) and a depth-budget whose lowest tier is the escalation `floor`
# (so the strategist can never encode a below-floor budget). Mirrors how coverage/surface ledgers are
# guarded, and keeps the agentic-upgrade wiring from silently rotting.
strat_dir = skills_dir / "strategist"
if strat_dir.is_dir():
    checked["strategist"] = 1
    for req in ("SKILL.md", "checklist.md", "review.md"):
        if not (strat_dir / req).is_file():
            err(f"strategist: missing {req} (the planning skill contract)")
    if (strat_dir / "verify.md").is_file():
        err("strategist: must be review-only (emits hunt_plan.json, not findings) — remove verify.md")
    sreview = strat_dir / "review.md"
    if sreview.is_file():
        sobj, sproblem = load_manifest(sreview)
        if sproblem:
            err(f"strategist/review.md: {sproblem}")
        elif not any(a.get("path") == "hunt_plan.json"
                     and a.get("schema") == "skills/_contract/hunt_plan.schema.json"
                     for a in sobj.get("artifacts", [])):
            err("strategist/review.md: manifest must declare hunt_plan.json with "
                "schema skills/_contract/hunt_plan.schema.json")

hp_path = skills_dir / "_contract" / "hunt_plan.schema.json"
if not hp_path.is_file():
    err("skills/_contract/hunt_plan.schema.json missing (the strategist's output schema)")
else:
    checked["hunt_plan_schema"] = 1
    try:
        hp = json.loads(hp_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        hp = None
        err(f"hunt_plan.schema.json: invalid JSON: {e}")
    if hp is not None:
        props = hp.get("properties") or {}
        if "version" not in props:
            err("hunt_plan.schema.json: must declare a root 'version' property (schema-versioning drift)")
        if hp.get("additionalProperties") is not False:
            err("hunt_plan.schema.json: root must be additionalProperties:false (closed ranking artifact)")
        defs = hp.get("$defs") or {}
        entry = defs.get("entry") or {}
        qstate = ((entry.get("properties") or {}).get("queue_state") or {}).get("enum") or []
        if "skipped" in qstate:
            err("hunt_plan.schema.json: queue_state enum must NOT include 'skipped' — the strategist "
                "can never skip a class (only coverage.py records a skip, with a reason)")
        if not qstate:
            err("hunt_plan.schema.json: $defs/entry/queue_state must declare an enum")
        budget = defs.get("depth_budget") or {}
        tiers = ((budget.get("properties") or {}).get("tier") or {}).get("enum") or []
        if tiers and tiers[0] != "floor":
            err("hunt_plan.schema.json: depth_budget.tier enum must start at 'floor' (the lowest budget "
                "is still the full escalation floor — a budget can never go below it)")
        if not tiers:
            err("hunt_plan.schema.json: $defs/depth_budget/tier must declare an enum (floor/standard/deep)")

# 20 — diagnostics schema: the engagement run-diagnostics contract (runtime/diagnostics.json). A
# closed, versioned coordination artifact the CLI writes and Phase 2 reads back. Registered here so
# a drift (a dropped root `version`, an opened-up root, or a missing pinned key) fails the suite.
dg_path = skills_dir / "_contract" / "diagnostics.schema.json"
if not dg_path.is_file():
    err("skills/_contract/diagnostics.schema.json missing (the engagement run-diagnostics contract)")
else:
    checked["diagnostics_schema"] = 1
    try:
        dg = json.loads(dg_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        dg = None
        err(f"diagnostics.schema.json: invalid JSON: {e}")
    if dg is not None:
        dprops = dg.get("properties") or {}
        if "version" not in dprops:
            err("diagnostics.schema.json: must declare a root 'version' property (schema-versioning drift)")
        if dg.get("additionalProperties") is not False:
            err("diagnostics.schema.json: root must be additionalProperties:false (closed artifact)")
        for req in ("engagement", "generated_at", "runs"):
            if req not in dprops:
                err(f"diagnostics.schema.json: root must declare a '{req}' property")
        run_def = ((dg.get("$defs") or {}).get("run") or {})
        if run_def.get("additionalProperties") is not False:
            err("diagnostics.schema.json: $defs/run must be additionalProperties:false (closed run record)")


# 21 — evidence-sufficiency score consistency: the quantified accept/downgrade floor. The schema field
# (finding.evidence_score), the contract instruction (verify-base.md), and the scorer's band constants
# (scripts/evidence_score.py) must stay in agreement, so a drift (a dropped field, a renamed band, a
# contract that stops telling reviewers to compute it) fails the suite. A standalone check fn + one call.
def check_evidence_score():
    checked["evidence_score"] = 1
    # (a) the schema declares finding.evidence_score, closed, with the floor bands + reliability fields.
    fsp = skills_dir / "_contract" / "finding.schema.json"
    es_schema = None
    if fsp.is_file():
        try:
            fd = json.loads(fsp.read_text(encoding="utf-8"))
            es_schema = (((fd.get("$defs") or {}).get("finding") or {}).get("properties") or {}).get("evidence_score")
        except json.JSONDecodeError:
            es_schema = None  # invalid-JSON already reported by check 4
    if not isinstance(es_schema, dict):
        err("finding.schema.json: $defs/finding must declare an 'evidence_score' property "
            "(the quantified evidence-sufficiency floor)")
    else:
        if es_schema.get("additionalProperties") is not False:
            err("finding.schema.json: evidence_score must be additionalProperties:false (closed scoring block)")
        esp = es_schema.get("properties") or {}
        for req in ("score", "decision", "components", "reliability_runs", "reliability_hits"):
            if req not in esp:
                err(f"finding.schema.json: evidence_score must declare a '{req}' property")
        dec_enum = set((esp.get("decision") or {}).get("enum") or [])
        if dec_enum != {"kill", "downgrade", "pass"}:
            err("finding.schema.json: evidence_score.decision enum must be exactly "
                f"['kill','downgrade','pass'] (got {sorted(dec_enum)})")
        score_p = esp.get("score") or {}
        if score_p.get("minimum") != 0 or score_p.get("maximum") != 100:
            err("finding.schema.json: evidence_score.score must be bounded 0..100")
    # (b) verify-base.md instructs every reviewer to COMPUTE the score, WRITE it, and apply the FLOOR.
    vbp = skills_dir / "_contract" / "verify-base.md"
    if not vbp.is_file():
        err("skills/_contract/verify-base.md missing (cannot check the evidence-score reviewer instruction)")
    else:
        vbt = vbp.read_text(encoding="utf-8", errors="replace")
        if "scripts/evidence_score.py" not in vbt:
            err("verify-base.md: must instruct reviewers to compute the score with scripts/evidence_score.py")
        if "evidence_score" not in vbt:
            err("verify-base.md: must tell reviewers to write the finding's evidence_score block")
        for band in ("55", "75"):
            if band not in vbt:
                err(f"verify-base.md: must state the evidence-score band threshold {band}")
    # (c) the scorer exists and its band constants AGREE with the schema/contract (55 / 75), selftest passes.
    esf = ROOT / "scripts" / "evidence_score.py"
    if not esf.is_file():
        err("scripts/evidence_score.py missing (the evidence-sufficiency scorer)")
        return
    try:
        import importlib.util
        _spec = importlib.util.spec_from_file_location("rs_evidence_score_lint", esf)
        _es = importlib.util.module_from_spec(_spec)
        sys.modules["rs_evidence_score_lint"] = _es  # dataclasses need the module registered
        _spec.loader.exec_module(_es)
        if (_es.BAND_KILL, _es.BAND_PASS) != (55, 75):
            err(f"evidence_score.py: band constants ({_es.BAND_KILL},{_es.BAND_PASS}) must be (55,75) "
                "to match the schema + verify-base.md")
        import io
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            _es.selftest()
    except BaseException as e:  # noqa: BLE001
        err(f"evidence_score.py selftest failed: {e}")


check_evidence_score()


# 22 — cross-model exhaustion-adversary wiring: the model-pinned agent, its verdict schema, and the hard
# gate that consumes it must all stay in agreement. The adversary disproves "engagement complete" on a
# DIFFERENT model (a same-model self-check is worthless), so a dropped model pin, a drifted verdict enum, or
# a gate that stops reading the artifact silently defeats "a gate you can route around isn't real".
def check_exhaustion_adversary():
    checked["exhaustion_adversary"] = 1
    # (a) the cross-model agent exists and carries a model pin (the whole point — not a same-model check).
    agent = ROOT / ".claude" / "agents" / "exhaustion-adversary.md"
    if not agent.is_file():
        err(".claude/agents/exhaustion-adversary.md missing (the cross-model exhaustion adversary)")
    else:
        keys = frontmatter_keys(agent)
        if keys is None:
            err(".claude/agents/exhaustion-adversary.md: missing frontmatter")
        elif "model" not in keys:
            err(".claude/agents/exhaustion-adversary.md: frontmatter must pin a 'model' (the cross-model "
                "discipline — a same-model 'are we done?' check is worthless)")
    # (b) the verdict schema is a closed, versioned artifact with exactly the two-verdict enum.
    scm = skills_dir / "_contract" / "exhaustion_review.schema.json"
    if not scm.is_file():
        err("skills/_contract/exhaustion_review.schema.json missing (the exhaustion-review verdict schema)")
    else:
        try:
            ex = json.loads(scm.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            ex = None
            err(f"exhaustion_review.schema.json: invalid JSON: {e}")
        if ex is not None:
            if "version" not in (ex.get("properties") or {}):
                err("exhaustion_review.schema.json: must declare a root 'version' property (schema-versioning drift)")
            if ex.get("additionalProperties") is not False:
                err("exhaustion_review.schema.json: root must be additionalProperties:false (closed verdict artifact)")
            verdict_enum = set(((ex.get("properties") or {}).get("verdict") or {}).get("enum") or [])
            if verdict_enum != {"no_gaps_found", "found_gaps"}:
                err("exhaustion_review.schema.json: verdict enum must be exactly "
                    f"['no_gaps_found','found_gaps'] (got {sorted(verdict_enum)})")
    # (c) the hard gate actually consumes the artifact (wiring present, not dead code).
    vcp = skills_dir / "_contract" / "verify_completion.py"
    if vcp.is_file():
        vct = vcp.read_text(encoding="utf-8", errors="replace")
        if "exhaustion_review.json" not in vct or "_exhaustion_review_check" not in vct:
            err("verify_completion.py: the exhaustion-adversary gate is not wired "
                "(expected runtime/exhaustion_review.json + _exhaustion_review_check)")


check_exhaustion_adversary()


# 22b — cross-model dispatch ledger (roadmap L-H): the `model_ledger.json` schema that MEASURES what the
# `model:` pin ASSERTS. A closed, versioned coordination artifact scripts/model_ledger.py writes and the
# completion gate reads back for its diversity-visibility warning. Registered here so a drift (a dropped root
# `version`, an opened-up root/entry, or a drifted role enum) fails the suite — mirrors the diagnostics /
# exhaustion-adversary schema checks.
def check_model_ledger():
    checked["model_ledger_schema"] = 1
    scm = skills_dir / "_contract" / "model_ledger.schema.json"
    if not scm.is_file():
        err("skills/_contract/model_ledger.schema.json missing (the cross-model dispatch ledger schema)")
    else:
        try:
            ml = json.loads(scm.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            ml = None
            err(f"model_ledger.schema.json: invalid JSON: {e}")
        if ml is not None:
            mprops = ml.get("properties") or {}
            if "version" not in mprops:
                err("model_ledger.schema.json: must declare a root 'version' property (schema-versioning drift)")
            if ml.get("additionalProperties") is not False:
                err("model_ledger.schema.json: root must be additionalProperties:false (closed artifact)")
            for req in ("engagement", "entries"):
                if req not in mprops:
                    err(f"model_ledger.schema.json: root must declare an '{req}' property")
            entry_def = ((ml.get("$defs") or {}).get("entry") or {})
            if entry_def.get("additionalProperties") is not False:
                err("model_ledger.schema.json: $defs/entry must be additionalProperties:false (closed record)")
            role_enum = set(((entry_def.get("properties") or {}).get("role") or {}).get("enum") or [])
            if role_enum != {"executor", "reviewer", "exhaustion-adversary", "secondary-review", "other"}:
                err("model_ledger.schema.json: $defs/entry/role enum must be exactly "
                    f"['executor','reviewer','exhaustion-adversary','secondary-review','other'] (got {sorted(role_enum)})")
            for req in ("role", "model", "ts"):
                if req not in (entry_def.get("required") or []):
                    err(f"model_ledger.schema.json: $defs/entry must require '{req}'")
    # the producer self-test must pass (family-normalize + record/read round-trip + diversity True/False)
    mlp = ROOT / "scripts" / "model_ledger.py"
    if not mlp.is_file():
        err("scripts/model_ledger.py missing (the cross-model dispatch-ledger producer)")
        return
    try:
        import importlib.util
        _mlspec = importlib.util.spec_from_file_location("rs_model_ledger_lint", mlp)
        _ml = importlib.util.module_from_spec(_mlspec)
        _mlspec.loader.exec_module(_ml)
        import io
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            _ml.selftest()
        checked["model_ledger"] = 1
    except BaseException as e:  # noqa: BLE001
        err(f"model_ledger.py selftest failed: {e}")


check_model_ledger()

check_vrt()

# report — guarded so the module can be imported (e.g. by scripts/tests/test_vrt.py) to exercise its
# pure helpers without the top-level scan exiting the interpreter. Running it as a script is unchanged.
if __name__ == "__main__":
    print("Redstrike validate.py")
    print("  checked: " + ", ".join(f"{v} {k}" for k, v in checked.items()))
    if errors:
        print(f"\nFAIL -- {len(errors)} problem(s):")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    print("\nPASS -- framework is consistent.")
    sys.exit(0)
