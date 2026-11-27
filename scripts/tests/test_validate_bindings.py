#!/usr/bin/env python3
"""
Unit tests for the skill-tool binding-symmetry check in scripts/validate.py (check #13b,
`skill_tool_binding_errors`) -- the fix for the strategist leak: `skills/strategist/` shipped with no
`.claude/skills/redstrike-strategist/` binding, so the orchestrator's §2.5 hunt-strategy Skill call was a
DEAD invocation on every engagement, and validate.py had no check to catch it.

Core guarantees:
  * the REAL repo tree is symmetric -- every invokable canonical skill has a Skill-tool binding, and every
    redstrike-<token> referenced in a SKILL.md resolves (the check PASSES as shipped);
  * the specific regression: `.claude/skills/redstrike-strategist/SKILL.md` now exists with frontmatter;
  * a synthesized missing-binding fixture FAILS (the gap that hid the leak is now caught);
  * the `_contract` meta dir (no SKILL.md, never invoked) is correctly EXCLUDED;
  * a redstrike-<token> that resolves to no binding is flagged, while a family-glob prefix
    (redstrike-xss-* naming the redstrike-xss-* family) correctly resolves.

validate.py's top-level repo scan is guarded behind `if __name__ == "__main__"`, so importing it here only
binds its pure helpers (no interpreter exit). Stdlib only, runnable as `python test_validate_bindings.py`.
"""
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
ROOT = HERE.parents[2]
sys.path.insert(0, str(SCRIPTS))

import validate as v  # noqa: E402

SKILLS = ROOT / "skills"
CSKILLS = ROOT / ".claude" / "skills"


def _mk_skill(base, name, body=""):
    """Create <base>/<name>/SKILL.md with a minimal valid frontmatter + optional body."""
    d = base / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: test skill {name}\n---\n\n{body}\n",
        encoding="utf-8")
    return d


class RealTree(unittest.TestCase):
    """The shipped repo must be symmetric -- this is the check running against reality."""

    def test_real_tree_is_symmetric(self):
        errs = v.skill_tool_binding_errors(SKILLS, CSKILLS)
        self.assertEqual(errs, [], f"the real tree must have no binding gaps, got: {errs}")

    def test_strategist_binding_exists(self):
        # the exact leak this fix closes: the strategist binding must now be present + frontmatter'd.
        stub = CSKILLS / "redstrike-strategist" / "SKILL.md"
        self.assertTrue(stub.is_file(), "the strategist Skill-tool binding stub must exist")
        keys = v.frontmatter_keys(stub)
        self.assertIsNotNone(keys, "the strategist stub must carry frontmatter")
        self.assertIn("name", keys)
        self.assertIn("description", keys)

    def test_every_invokable_skill_has_a_binding(self):
        # independent recomputation of the invariant (not trusting the function alone).
        invokable = {p.name for p in SKILLS.iterdir() if p.is_dir() and p.name != "_contract"}
        bindings = {p.name for p in CSKILLS.iterdir() if p.is_dir()}
        missing = sorted(x for x in invokable if (CSKILLS / f"redstrike-{x}" / "SKILL.md").is_file() is False)
        self.assertEqual(missing, [], f"invokable skills missing a binding: {missing}")
        self.assertTrue({f"redstrike-{x}" for x in invokable} <= bindings)


class MissingBindingFixture(unittest.TestCase):
    """A synthesized tree proves the check FAILS when a binding is absent (the gap that hid the leak)."""

    def test_missing_binding_is_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            skills = tmp / "skills"
            cskills = tmp / ".claude" / "skills"
            _mk_skill(skills, "foo")                 # invokable skill, NO binding
            (skills / "_contract").mkdir(parents=True)  # meta dir, correctly excluded
            cskills.mkdir(parents=True)              # empty bindings dir
            errs = v.skill_tool_binding_errors(skills, cskills)
            self.assertTrue(errs, "a missing binding must be flagged")
            self.assertTrue(any("skills/foo/" in e and "redstrike-foo" in e for e in errs),
                            f"the foo gap must be named, got: {errs}")
            self.assertFalse(any("_contract" in e for e in errs),
                             "the _contract meta dir must NOT be treated as an invokable skill")

    def test_present_binding_passes(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            skills = tmp / "skills"
            cskills = tmp / ".claude" / "skills"
            _mk_skill(skills, "foo")
            _mk_skill(cskills, "redstrike-foo")      # the binding now present
            self.assertEqual(v.skill_tool_binding_errors(skills, cskills), [],
                             "a fully-bound fixture must pass clean")

    def test_binding_dir_without_skill_md_is_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            skills = tmp / "skills"
            cskills = tmp / ".claude" / "skills"
            _mk_skill(skills, "foo")
            (cskills / "redstrike-foo").mkdir(parents=True)  # dir exists but NO SKILL.md inside
            errs = v.skill_tool_binding_errors(skills, cskills)
            self.assertTrue(any("redstrike-foo/SKILL.md" in e for e in errs),
                            "a binding dir with no SKILL.md must still be flagged")


class TokenResolution(unittest.TestCase):
    """Every redstrike-<token> in a SKILL.md must resolve to a binding, directly or as a family glob."""

    def test_unresolved_token_is_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            skills = tmp / "skills"
            cskills = tmp / ".claude" / "skills"
            _mk_skill(skills, "foo", body="hand off to `redstrike-nonexistent` for the next step")
            _mk_skill(cskills, "redstrike-foo")      # foo is bound, so only the token error can fire
            errs = v.skill_tool_binding_errors(skills, cskills)
            self.assertTrue(any("redstrike-nonexistent" in e for e in errs),
                            f"an unresolved token must be flagged, got: {errs}")

    def test_family_glob_prefix_resolves(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            skills = tmp / "skills"
            cskills = tmp / ".claude" / "skills"
            # a binding under the foo-bar family; the SKILL.md references the glob redstrike-foo-*
            _mk_skill(skills, "foo-bar", body="the whole `redstrike-foo-*` family runs here")
            _mk_skill(cskills, "redstrike-foo-bar")
            self.assertEqual(v.skill_tool_binding_errors(skills, cskills), [],
                             "a redstrike-foo-* glob must resolve against the redstrike-foo-bar binding")


if __name__ == "__main__":
    unittest.main()
