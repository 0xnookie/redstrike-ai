import io
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock as mock
from contextlib import redirect_stdout

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # cli/

from redstrike_cli import scope as scopemod  # noqa: E402
from redstrike_cli import source_audit, yamlio  # noqa: E402
from redstrike_cli.__main__ import main  # noqa: E402


class TestNormalizeUrl(unittest.TestCase):
    def test_accepts_https_http_git(self):
        for u in ("https://example.com/acme/widgets.git",
                  "http://example.com/acme/widgets",
                  "git://example.com/acme/widgets.git"):
            self.assertEqual(source_audit.normalize_url(u), u)

    def test_rejects_file_scheme(self):
        with self.assertRaises(ValueError):
            source_audit.normalize_url("file:///etc/passwd")

    def test_rejects_ssh_and_scp_style(self):
        for u in ("ssh://git@example.com/acme/widgets.git", "git@example.com:acme/widgets.git"):
            with self.assertRaises(ValueError):
                source_audit.normalize_url(u)

    def test_rejects_transport_smuggling(self):
        with self.assertRaises(ValueError):
            source_audit.normalize_url("ext::sh -c 'id'")

    def test_rejects_embedded_credentials(self):
        with self.assertRaises(ValueError):
            source_audit.normalize_url("https://user:token@example.com/acme/widgets.git")

    def test_rejects_leading_dash_whitespace_empty(self):
        for u in ("--upload-pack=touch /tmp/x", "https://example.com/a b", "", "   "):
            with self.assertRaises(ValueError):
                source_audit.normalize_url(u)

    def test_repo_name_from_url(self):
        self.assertEqual(source_audit.repo_name_from_url("https://example.com/acme/widgets.git"), "widgets")
        self.assertEqual(source_audit.repo_name_from_url("https://example.com/acme/Big_Service/"), "big-service")


def _git(args, cwd, **kw):
    subprocess.run(["git", *args], cwd=str(cwd), check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kw)


@unittest.skipUnless(shutil.which("git"), "git required")
class TestRealCloneAgainstLocalFixture(unittest.TestCase):
    """Exercise the REAL git clone + commit/branch resolution against a LOCAL fixture — no network.
    The file transport is enabled only for this test; production keeps it blocked."""

    def test_clone_resolves_commit_and_branch(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            fixture = root / "fixture"
            fixture.mkdir()
            _git(["init", "-b", "main"], fixture)
            (fixture / "app.py").write_text("print('hello')\n", encoding="utf-8")
            _git(["-c", "user.email=t@t", "-c", "user.name=t", "add", "-A"], fixture)
            _git(["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "init"], fixture)

            dest = root / "clone"
            info = source_audit.clone(
                str(fixture), dest,
                allow_protocols=("file", "http", "https", "git"),
            )
            self.assertEqual(info["branch"], "main")
            self.assertRegex(info["commit"], r"^[0-9a-f]{40}$")
            self.assertTrue((dest / "app.py").is_file())

    def test_clone_refuses_file_scheme_by_default(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            fixture = root / "fixture"
            fixture.mkdir()
            _git(["init", "-b", "main"], fixture)
            (fixture / "x").write_text("x", encoding="utf-8")
            _git(["-c", "user.email=t@t", "-c", "user.name=t", "add", "-A"], fixture)
            _git(["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "c"], fixture)
            # the default transport allowlist has no `file`, so a local/file clone must be refused
            with self.assertRaises(source_audit.CloneError):
                source_audit.clone(str(fixture), root / "clone")


class TestAuditScaffoldsSourceBlock(unittest.TestCase):
    """End-to-end `redstrike audit` with the clone monkeypatched: proves a source-granted scope.yaml
    with the correct `source:` block is produced (no network)."""

    def _fake_clone(self, url, dest, **kw):
        dest = pathlib.Path(dest)
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "README.md").write_text("fixture\n", encoding="utf-8")
        return {"commit": "a" * 40, "branch": "main"}

    def test_dry_run_scope_yaml_has_source_block(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            (repo / "engagements").mkdir()
            with mock.patch("redstrike_cli.source_audit.clone", side_effect=self._fake_clone):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = main([
                        "--repo", str(repo), "--no-color", "--no-banner",
                        "audit", "https://example.com/acme/widgets.git",
                        "--authorized-by", "sec@acme / auth-7",
                        "--i-confirm-authorization",
                        "--no-launch",
                    ])
            self.assertEqual(rc, 0, buf.getvalue())

            # resolve the engagement dir (single one); its id is widgets-<date>
            engs = [p for p in (repo / "engagements").iterdir() if (p / "scope.yaml").is_file()]
            self.assertEqual(len(engs), 1)
            eng = engs[0]
            self.assertTrue(eng.name.startswith("widgets-"))

            # the clone landed under source/ and the scope.yaml carries the shared source: block
            self.assertTrue((eng / "source" / "README.md").is_file())
            doc = yamlio.load(eng / "scope.yaml")
            self.assertIn("source", doc)
            self.assertEqual(doc["source"]["repo_url"], "https://example.com/acme/widgets.git")
            self.assertEqual(doc["source"]["local_path"], "source/")
            self.assertEqual(doc["source"]["commit"], "a" * 40)
            self.assertEqual(doc["source"]["branch"], "main")
            # the repo URL is recorded as the in-scope target, so the shared launch gate passes
            self.assertIn("https://example.com/acme/widgets.git", doc["in_scope"]["urls"])
            ok, problems = scopemod.is_complete(scopemod.build_projection(doc))
            self.assertTrue(ok, problems)
            # and the runtime projection carries the source grant (source_repo)
            proj = scopemod.build_projection(doc)
            self.assertEqual(proj["source_repo"]["commit"], "a" * 40)

    def test_invalid_url_refused_before_any_fs_work(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            (repo / "engagements").mkdir()
            with mock.patch("redstrike_cli.source_audit.clone") as cl:
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = main([
                        "--repo", str(repo), "--no-color", "--no-banner",
                        "audit", "file:///etc/passwd",
                        "--authorized-by", "x", "--i-confirm-authorization", "--no-launch",
                    ])
            self.assertEqual(rc, 2, buf.getvalue())
            cl.assert_not_called()
            self.assertEqual(list((repo / "engagements").iterdir()), [])

    def test_missing_authorization_refused(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            (repo / "engagements").mkdir()
            with mock.patch("redstrike_cli.source_audit.clone", side_effect=self._fake_clone) as cl:
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = main([
                        "--repo", str(repo), "--no-color", "--no-banner",
                        "audit", "https://example.com/acme/widgets.git",
                        "--authorized-by", "sec@acme",  # but NOT --i-confirm-authorization (non-interactive)
                        "--no-launch",
                    ])
            self.assertEqual(rc, 2, buf.getvalue())
            cl.assert_not_called()


if __name__ == "__main__":
    unittest.main()
