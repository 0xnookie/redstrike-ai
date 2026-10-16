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
