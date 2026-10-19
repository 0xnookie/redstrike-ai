import io
import json
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # cli/

from redstrike_cli import engagement, launch  # noqa: E402
from redstrike_cli.__main__ import main  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[2]


class TestInitAndRunDryRun(unittest.TestCase):
    def test_full_flow(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            (repo / "engagements").mkdir()

            rc = main([
                "--repo", str(repo), "--no-color", "--no-banner",
                "init", "Acme Corp",
                "--authorized-by", "sec@acme / auth-123",
                "--domain", "*.acme.com", "--domain", "api.acme.com",
                "--cidr", "203.0.113.0/24",
                "--exclude-domain", "admin.acme.com",
                "--i-confirm-authorization",
            ])
            self.assertEqual(rc, 0)

            eid = engagement.engagement_id("Acme Corp")
            eng = repo / "engagements" / eid
            self.assertTrue((eng / "scope.yaml").is_file())
            self.assertTrue((eng / "runtime" / "authorization.json").is_file())
            self.assertTrue((eng / "findings" / "evidence").is_dir())
            auth = json.loads((eng / "runtime" / "authorization.json").read_text(encoding="utf-8"))
            self.assertTrue(auth["operator_confirmed"])

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main([
                    "--repo", str(repo), "--no-color", "--no-banner",
                    "run", eid, "--dry-run",
                ])
            out = buf.getvalue()
            self.assertEqual(rc, 0, out)
            # generated runtime artifacts
            self.assertTrue((eng / "runtime" / "scope.json").is_file())
            self.assertTrue((eng / "runtime" / "settings.json").is_file())
            self.assertTrue((eng / "runtime" / "roe.md").is_file())
            settings = json.loads((eng / "runtime" / "settings.json").read_text(encoding="utf-8"))
            self.assertIn("PreToolUse", settings["hooks"])
            # dry-run prints the argv with the key flags
            self.assertIn("--append-system-prompt-file", out)
            self.assertIn("--add-dir", out)
            self.assertIn("--permission-mode", out)

    def test_init_refuses_without_confirmation_noninteractive(self):
        import unittest.mock as mock

        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            (repo / "engagements").mkdir()
            # Force non-interactive: a StringIO stdin reports isatty()==False.
            with mock.patch("sys.stdin", io.StringIO("")), redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    main([
                        "--repo", str(repo), "--no-banner",
                        "init", "Acme", "--authorized-by", "x", "--domain", "*.acme.com",
                        # no --i-confirm-authorization
                    ])


class TestBuildArgv(unittest.TestCase):
    def test_argv_shape(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            fields = engagement.build_fields(
                client="Acme", authorized_by="sec@acme", domains=["*.acme.com"]
            )
            engagement.scaffold(repo, fields, operator="tester")
            eng = repo / "engagements" / fields["engagement"]
            prep = launch.prepare_runtime(eng, repo, "/usr/bin/python3")
            argv = launch.build_argv("claude", repo, prep, "do it", "default")
            self.assertEqual(argv[0], "claude")
            self.assertIn("--settings", argv)
            self.assertIn("--session-id", argv)
            self.assertIn(str(prep.roe_path), argv)
            self.assertEqual(launch.gate(prep), [])  # fresh window is open + complete


if __name__ == "__main__":
    unittest.main()
