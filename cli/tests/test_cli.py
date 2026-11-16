import hashlib
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # cli/

import unittest.mock as mock  # noqa: E402

from redstrike_cli import engagement, gate, launch, preflight  # noqa: E402
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
            # the OS-sandbox network boundary is derived from the engagement scope (P0-1)
            self.assertIn("sandbox", settings)
            self.assertIs(settings["sandbox"]["enabled"], True)
            allowed_domains = settings["sandbox"]["network"]["allowedDomains"]
            self.assertIn("api.anthropic.com", allowed_domains)  # engine host always present
            self.assertIn("*.acme.com", allowed_domains)
            self.assertIn("api.acme.com", allowed_domains)
            self.assertNotIn("admin.acme.com", allowed_domains)  # explicit exclude dropped
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


class TestConsole(unittest.TestCase):
    def test_console_dry_run_prints_argv(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            (repo / "engagements").mkdir()
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main([
                    "--repo", str(repo), "--no-color", "--no-banner",
                    "console", "--dry-run", "--background",
                ])
            out = buf.getvalue()
            self.assertEqual(rc, 0, out)
            self.assertIn(os.path.join("scripts", "console.py"), out)
            self.assertIn("--background", out)
            self.assertIn("--open", out)
            self.assertIn(str(repo / "engagements"), out)

    def test_run_console_dry_run_does_not_launch(self):
        # a dry-run must prepare the argv but never bring up the console
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            (repo / "engagements").mkdir()
            main([
                "--repo", str(repo), "--no-color", "--no-banner",
                "init", "Acme", "--authorized-by", "x", "--domain", "*.acme.com",
                "--i-confirm-authorization",
            ])
            eid = engagement.engagement_id("Acme")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main([
                    "--repo", str(repo), "--no-color", "--no-banner",
                    "run", eid, "--dry-run", "--console",
                ])
            out = buf.getvalue()
            self.assertEqual(rc, 0, out)
            self.assertNotIn("bringing up the web console", out)


class TestSandboxBanner(unittest.TestCase):
    def test_status_windows_is_off(self):
        with mock.patch.object(preflight, "is_windows", return_value=True):
            ok, detail = preflight.sandbox_status()
        self.assertFalse(ok)
        self.assertIn("NO OS sandbox", detail)

    def test_status_deps_missing_is_limited(self):
        with mock.patch.object(preflight, "is_windows", return_value=False), \
             mock.patch.object(preflight, "sandbox_deps", return_value=(False, ["bwrap"])):
            ok, detail = preflight.sandbox_status()
        self.assertFalse(ok)
        self.assertIn("LIMITED", detail)

    def test_status_ok_when_present(self):
        with mock.patch.object(preflight, "is_windows", return_value=False), \
             mock.patch.object(preflight, "sandbox_deps", return_value=(True, [])):
            ok, _ = preflight.sandbox_status()
        self.assertTrue(ok)

    def test_run_prints_banner_when_confinement_off(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            (repo / "engagements").mkdir()
            main(["--repo", str(repo), "--no-color", "--no-banner",
                  "init", "Acme", "--authorized-by", "x", "--domain", "*.acme.com",
                  "--i-confirm-authorization"])
            eid = engagement.engagement_id("Acme")
            buf = io.StringIO()
            with mock.patch("redstrike_cli.preflight.sandbox_status",
                            return_value=(False, "CONFINEMENT-OFF-marker")), redirect_stdout(buf):
                rc = main(["--repo", str(repo), "--no-color", "--no-banner", "run", eid, "--dry-run"])
            out = buf.getvalue()
            self.assertEqual(rc, 0, out)
            self.assertIn("CONFINEMENT-OFF-marker", out)
            self.assertIn("network confinement", out)

    def test_run_no_banner_when_confinement_ok(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            (repo / "engagements").mkdir()
            main(["--repo", str(repo), "--no-color", "--no-banner",
                  "init", "Acme", "--authorized-by", "x", "--domain", "*.acme.com",
                  "--i-confirm-authorization"])
            eid = engagement.engagement_id("Acme")
            buf = io.StringIO()
            with mock.patch("redstrike_cli.preflight.sandbox_status", return_value=(True, "ok")), \
                 redirect_stdout(buf):
                main(["--repo", str(repo), "--no-color", "--no-banner", "run", eid, "--dry-run"])
            self.assertNotIn("network confinement", buf.getvalue())


class TestScopeIntegrity(unittest.TestCase):
    def _scaffold(self, repo: pathlib.Path) -> pathlib.Path:
        (repo / "engagements").mkdir()
        fields = engagement.build_fields(client="Acme", authorized_by="sec@acme", domains=["*.acme.com"])
        engagement.scaffold(repo, fields, operator="t")
        return repo / "engagements" / fields["engagement"]

    def test_scaffold_records_acknowledged_sha(self):
        with tempfile.TemporaryDirectory() as d:
            eng = self._scaffold(pathlib.Path(d))
            auth = json.loads((eng / "runtime" / "authorization.json").read_text(encoding="utf-8"))
            expected = hashlib.sha256((eng / "scope.yaml").read_bytes()).hexdigest()
            self.assertEqual(auth["scope_sha256"], expected)

    def test_prepare_no_warning_when_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            eng = self._scaffold(repo)
            prep = launch.prepare_runtime(eng, repo, sys.executable)
            self.assertEqual(prep.scope_integrity_warning, "")
            self.assertTrue(prep.scope_sha256)

    def test_prepare_warns_on_scope_drift(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            eng = self._scaffold(repo)
            p = eng / "scope.yaml"
            p.write_text(p.read_text(encoding="utf-8") + "\n# an edit after acknowledgment\n", encoding="utf-8")
            prep = launch.prepare_runtime(eng, repo, sys.executable)
            self.assertIn("CHANGED", prep.scope_integrity_warning)

    def test_no_baseline_is_not_flagged(self):
        # an engagement with no recorded scope_sha256 (pre-integrity) must not be falsely flagged
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            eng = self._scaffold(repo)
            auth_path = eng / "runtime" / "authorization.json"
            auth = json.loads(auth_path.read_text(encoding="utf-8"))
            auth.pop("scope_sha256", None)
            auth_path.write_text(json.dumps(auth), encoding="utf-8")
            prep = launch.prepare_runtime(eng, repo, sys.executable)
            self.assertEqual(prep.scope_integrity_warning, "")


class TestCoverageWiring(unittest.TestCase):
    """E1: the CLI seeds + enforces the coverage ledger instead of leaving it to the model."""

    def test_coverage_validate_skips_when_script_absent(self):
        # no scripts/coverage.py in the repo -> nothing to enforce, must not break the gate
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            eng = repo / "eng"
            eng.mkdir()
            self.assertEqual(gate.coverage_validate(repo, eng), 0)

    def test_seed_creates_ledger_and_gate_flags_an_unrun_one(self):
        if not (REPO / "scripts" / "coverage.py").is_file():
            self.skipTest("real coverage.py not present")
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d) / "acme-eng"
            launch._seed_coverage_ledger(eng, REPO, sys.executable)
            led = eng / "coverage_ledger.json"
            self.assertTrue(led.is_file(), "seed must create the ledger")
            data = json.loads(led.read_text(encoding="utf-8"))
            self.assertTrue(any(c["status"] == "pending" for c in data["categories"]))
            # an all-pending (never-run) ledger is an incomplete-coverage gap -> gate fails
            self.assertNotEqual(gate.coverage_validate(REPO, eng), 0)
            # re-seeding must not clobber an existing ledger
            mtime = led.stat().st_mtime_ns
            launch._seed_coverage_ledger(eng, REPO, sys.executable)
            self.assertEqual(led.stat().st_mtime_ns, mtime)


if __name__ == "__main__":
    unittest.main()
