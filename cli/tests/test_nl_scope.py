"""Tests for Feature 3 — NL → DRAFT scope.yaml seeder (nl_scope.py) + the `scope` CLI command.

Covers:
  • parse_nl_scope: the worked example; keyword-delimited parsing so an exclude never leaks into the
    allow list; hosts / wildcards / cidrs / urls / ports / excluded hosts.
  • render_draft: the DRAFT banner + an UNSIGNED authorized_by placeholder, and a round-trip through
    the scope loader that scope.is_complete() REFUSES (draft is not launchable until signed).
  • the advisory notes carry the path/port advisories on a single YAML-safe line.
  • CLI: `redstrike scope --from-nl` runs without a repo and makes the draft-only posture explicit;
    `--out` writes the draft; and `accounts refresh` with no recipes is a safe no-op.
"""
import io
import json
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # cli/

from redstrike_cli import nl_scope, scope, yamlio  # noqa: E402
from redstrike_cli.__main__ import main  # noqa: E402


class TestParse(unittest.TestCase):
    def test_worked_example(self):
        p = nl_scope.parse_nl_scope("only /api/* no /logout host x.com")
        self.assertEqual(p["allow_paths"], ["/api/*"])
        self.assertEqual(p["exclude_paths"], ["/logout"])
        self.assertEqual(p["domains"], ["x.com"])

    def test_keywords_do_not_bleed(self):
        # "no /logout" must NOT land in allow_paths even though it follows "only ..."
        p = nl_scope.parse_nl_scope("only /api/* /v1/* no /logout /admin")
        self.assertEqual(sorted(p["allow_paths"]), ["/api/*", "/v1/*"])
        self.assertEqual(sorted(p["exclude_paths"]), ["/admin", "/logout"])

    def test_hosts_wildcards_cidrs_urls_ports_excludes(self):
        p = nl_scope.parse_nl_scope(
            "host x.com and *.example.com cidr 10.0.0.0/24 https://api.x.com/v2 "
            "ports 80,443,8080 exclude admin.example.com")
        self.assertIn("x.com", p["domains"])
        self.assertIn("*.example.com", p["domains"])
        self.assertIn("10.0.0.0/24", p["cidrs"])
        self.assertIn("https://api.x.com/v2", p["urls"])
        self.assertEqual(p["ports"], [80, 443, 8080])
        self.assertEqual(p["exclude_domains"], ["admin.example.com"])
        self.assertNotIn("admin.example.com", p["domains"])  # exclude not also in-scope

    def test_empty(self):
        p = nl_scope.parse_nl_scope("")
        self.assertEqual(p["domains"], [])
        self.assertEqual(p["ports"], [])

    def test_filename_not_a_host(self):
        p = nl_scope.parse_nl_scope("host scope.yaml")  # a path-looking token is not a target host
        self.assertEqual(p["domains"], [])


class TestDraft(unittest.TestCase):
    def test_unsigned_and_round_trips_blocked(self):
        parsed = nl_scope.parse_nl_scope("host x.com only /api/* ports 8080")
        draft = nl_scope.render_draft(parsed, nl_text="host x.com only /api/* ports 8080")
        self.assertIn("NOT AN AUTHORIZATION RECORD", draft)
        self.assertIn(nl_scope.UNSIGNED, draft)
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "scope.yaml"
            p.write_text(draft, encoding="utf-8")
            proj = scope.build_projection(yamlio.load(p))
            self.assertEqual(proj["in_scope"]["domains"], ["x.com"])
            ok, problems = scope.is_complete(proj)
            self.assertFalse(ok)  # NOT launchable until a human signs it
            self.assertTrue(any("authorized_by" in x for x in problems))
            # advisory path/port captured in notes (single YAML-safe line, no newline break)
            notes = yamlio.load(p).get("notes", "")
            self.assertIn("allow-paths=/api/*", notes)
            self.assertIn("ports=8080", notes)

    def test_client_defaults_to_first_host(self):
        parsed = nl_scope.parse_nl_scope("host acme.com")
        fields = nl_scope.draft_fields(parsed, nl_text="host acme.com")
        self.assertTrue(fields["engagement"].startswith("acme-com-"))


class TestScopeCLI(unittest.TestCase):
    def test_scope_command_no_repo_and_draft_posture(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--no-color", "--no-banner", "scope",
                       "--from-nl", "only /api/* no /logout host x.com"])
        out = buf.getvalue()
        self.assertEqual(rc, 0, out)
        self.assertIn("DRAFT ONLY", out)
        self.assertIn("NOT an authorization", out)
        self.assertIn("SIGNED scope.yaml", out)
        self.assertIn(nl_scope.UNSIGNED, out)  # the draft body is printed

    def test_scope_out_writes_file(self):
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d) / "draft.yaml"
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["--no-color", "--no-banner", "scope",
                           "--from-nl", "host x.com", "--out", str(out)])
            self.assertEqual(rc, 0, buf.getvalue())
            self.assertTrue(out.is_file())
            self.assertIn(nl_scope.UNSIGNED, out.read_text(encoding="utf-8"))
            # refuses to clobber without --force
            rc2 = main(["--no-color", "--no-banner", "scope", "--from-nl", "host y.com", "--out", str(out)])
            self.assertEqual(rc2, 1)


class TestAccountsRefreshCLI(unittest.TestCase):
    def test_refresh_noop_without_recipes(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            eng = repo / "engagements" / "acme-2026-01-01"
            (eng / "runtime").mkdir(parents=True)
            (eng / "scope.yaml").write_text("engagement: acme\n", encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["--repo", str(repo), "--no-color", "--no-banner",
                           "accounts", "refresh", "acme-2026-01-01"])
            self.assertEqual(rc, 0, buf.getvalue())
            self.assertIn("no test accounts", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
