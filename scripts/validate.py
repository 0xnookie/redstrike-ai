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
        elif any(a.get("path") == "findings.json" for a in obj.get("artifacts", [])):
            if not (sk / "verify.md").is_file():
                err(f"{sk.name}: manifest declares findings.json but has no verify.md")

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

# 9 — recall-benchmark self-test (target specs valid + category map in sync with the routing map)
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
    except BaseException as e:  # noqa: BLE001
        err(f"benchmark.py selftest failed: {e}")

# 10 — cve_prioritize self-test (KEV/EPSS/reachability/CVSS ranking logic)
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
