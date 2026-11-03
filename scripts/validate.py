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

# report
print("Redstrike validate.py")
print("  checked: " + ", ".join(f"{v} {k}" for k, v in checked.items()))
if errors:
    print(f"\nFAIL -- {len(errors)} problem(s):")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)
print("\nPASS -- framework is consistent.")
sys.exit(0)
