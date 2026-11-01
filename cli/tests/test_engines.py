import io
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # cli/

from redstrike_cli import engagement, engines, launch  # noqa: E402
from redstrike_cli.__main__ import main  # noqa: E402


class TestRegistry(unittest.TestCase):
    def test_default_is_claude_code_and_gated(self):
        eng = engines.get_engine()
        self.assertEqual(eng.name, "claude-code")
        self.assertTrue(eng.supports_tool_gating)
        self.assertIn("claude-code", engines.available())

    def test_ungated_engine_refused_by_default(self):
        with self.assertRaises(RuntimeError):
            engines.get_engine("codex")
        # lab/offline escape hatch
        self.assertEqual(engines.get_engine("codex", allow_ungated=True).name, "codex")
        self.assertNotIn("codex", engines.available())

    def test_unknown_engine(self):
        with self.assertRaises(KeyError):
            engines.get_engine("does-not-exist")

    def test_skeleton_explodes_only_on_use(self):
        codex = engines.get_engine("codex", allow_ungated=True)  # import/construct is fine
        with self.assertRaises(NotImplementedError):
            codex.prepare("x", "y", "py")


class _FakeEngine(engines.Engine):
    """A gated engine that records the dispatch and delegates prepare to the real launcher
    (so the scope summary still renders), proving cmd_run routes through the selected engine."""
    name = "fake"
    supports_tool_gating = True

    def __init__(self):
        self.calls: list[str] = []

    def preflight(self, repo):
        return []

    def is_available(self) -> bool:
        return False  # force the "print the plan" path without needing a real engine binary

    def auth_status(self):
        return (True, "")

    def prepare(self, engagement_dir, repo, python_exe, *, mode="interactive", extra_allow=None):
        self.calls.append(f"prepare:{mode}")
        return launch.prepare_runtime(engagement_dir, repo, python_exe, mode=mode, extra_allow=extra_allow)

    def gate(self, prep):
        self.calls.append("gate")
        return []

    def runtime_artifacts(self, prep, repo):
        return [("fake-config", "runtime/fake.json"), ("session", prep.session_id)]

    def build_invocation(self, prep, repo, prompt, *, mode="interactive", permission_mode="default",
                         allow=None, max_turns=200, max_budget=20.0, resume=False):
        self.calls.append(f"build:{mode}")
        allowed = ["Read", "WebFetch"] if mode == "autonomous" else None
        return engines.Invocation(argv=["fake-engine-bin", "--go", prompt], allowed=allowed)

    def run(self, prep, eng_dir, inv, *, mode="interactive", audit=None):
        self.calls.append(f"run:{mode}")
        return engines.RunResult(rc=0)


class TestRunWiring(unittest.TestCase):
    def _scaffold(self, repo: pathlib.Path) -> str:
        (repo / "engagements").mkdir()
        fields = engagement.build_fields(client="Acme", authorized_by="s", domains=["*.a.com"])
        engagement.scaffold(repo, fields, operator="t")
        return fields["engagement"]

    def test_run_dispatches_through_selected_engine(self):
        fake = _FakeEngine()
        # register a factory returning THIS instance so we can inspect .calls afterwards
        engines._REGISTRY["fake"] = lambda: fake  # type: ignore[assignment]
        try:
            with tempfile.TemporaryDirectory() as d:
                repo = pathlib.Path(d)
                eid = self._scaffold(repo)
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = main(["--repo", str(repo), "--no-color", "--no-banner",
                               "--engine", "fake", "run", eid, "--dry-run"])
                out = buf.getvalue()
            self.assertEqual(rc, 0, out)
            # dispatch actually went through the fake engine
            self.assertIn("prepare:interactive", fake.calls)
            self.assertIn("gate", fake.calls)
            self.assertIn("build:interactive", fake.calls)
            # and its invocation + artifacts were printed on the dry run
            self.assertIn("fake-engine-bin", out)
            self.assertIn("fake-config", out)
        finally:
            engines._REGISTRY.pop("fake", None)

    def test_ungated_engine_blocks_run_with_rc2(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            eid = self._scaffold(repo)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["--repo", str(repo), "--no-color", "--no-banner",
                           "--engine", "codex", "run", eid, "--dry-run"])
            out = buf.getvalue()
        self.assertEqual(rc, 2, out)
        self.assertIn("fail-closed", out.lower())  # refused before any launch

    def test_default_engine_run_dry_run_unchanged(self):
        # the claude-code path must behave exactly as before (artifacts + key flags)
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            eid = self._scaffold(repo)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["--repo", str(repo), "--no-color", "--no-banner", "run", eid, "--dry-run"])
            out = buf.getvalue()
            eng = repo / "engagements" / eid
            self.assertEqual(rc, 0, out)
            self.assertTrue((eng / "runtime" / "settings.json").is_file())
            self.assertIn("--append-system-prompt-file", out)
            self.assertIn("--add-dir", out)


if __name__ == "__main__":
    unittest.main()
