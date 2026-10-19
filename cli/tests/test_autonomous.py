import io
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # cli/

from redstrike_cli import autorun, engagement, launch, roe, settings  # noqa: E402


class TestAutonomousSettings(unittest.TestCase):
    def test_allowlist_defaults_and_opt_in(self):
        base = settings.autonomous_allowlist()
        self.assertIn("WebFetch", base)
        self.assertNotIn("Bash", base)  # shell is opt-in only
        ex = settings.autonomous_allowlist(["Bash(nmap *)", "WebFetch"])
        self.assertIn("Bash(nmap *)", ex)
        self.assertEqual(ex.count("WebFetch"), 1)  # deduped

    def test_render_settings_mode(self):
        s = settings.render_settings(
            python_exe="py", hook_script=pathlib.Path("/h.py"), scope_json=pathlib.Path("/s.json"),
            mode="autonomous", extra_allow=["Bash"],
        )
        self.assertIn("WebFetch", s["permissions"]["allow"])
        self.assertIn("Bash", s["permissions"]["allow"])
        si = settings.render_settings(
            python_exe="py", hook_script=pathlib.Path("/h.py"), scope_json=pathlib.Path("/s.json"),
        )
        self.assertNotIn("WebFetch", si["permissions"]["allow"])  # interactive stays read-only


class TestAutonomousArgv(unittest.TestCase):
    def test_argv_shape(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            fields = engagement.build_fields(client="Acme", authorized_by="s", domains=["*.a.com"])
            engagement.scaffold(repo, fields, operator="t")
            eng = repo / "engagements" / fields["engagement"]
            prep = launch.prepare_runtime(eng, repo, "py", mode="autonomous")
            allowed = ["Read", "WebFetch", "Bash(nmap *)"]
            argv = launch.build_autonomous_argv("claude", repo, prep, "go", allowed, max_turns=50, max_budget=5.0)
            for tok in ("-p", "stream-json", "dontAsk", "--max-turns", "50", "--session-id", "--strict-mcp-config"):
                self.assertIn(tok, argv)
            i = argv.index("--allowedTools")  # must be last, consuming the allowlist
            self.assertEqual(argv[i + 1:], allowed)
            rargv = launch.build_autonomous_argv("claude", repo, prep, "go", allowed, max_turns=50, max_budget=5.0, resume=True)
            self.assertIn("--resume", rargv)
            self.assertNotIn("--session-id", rargv)


class TestAutorunParser(unittest.TestCase):
    def test_handle_events(self):
        s = autorun.RunSummary()
        buf = io.StringIO()
        autorun.handle_event(
            {"type": "system", "subtype": "init", "model": "m",
             "slash_commands": ["redstrike", "redstrike-xss-reflected", "other"], "mcp_servers": []},
            s, buf,
        )
        self.assertEqual(s.skills_loaded, 2)
        autorun.handle_event(
            {"type": "assistant", "message": {"content": [
                {"type": "tool_use", "name": "Bash", "input": {"command": "nmap x"}},
                {"type": "text", "text": "hi"}]}},
            s, buf,
        )
        self.assertEqual(s.tool_calls, 1)
        autorun.handle_event(
            {"type": "result", "subtype": "success", "num_turns": 3, "total_cost_usd": 0.12,
             "stop_reason": "end_turn", "permission_denials": [{"tool_name": "Bash"}], "result": "done\nmore"},
            s, buf,
        )
        self.assertEqual(s.subtype, "success")
        self.assertEqual(s.num_turns, 3)
        self.assertEqual(len(s.denials), 1)
        self.assertAlmostEqual(s.cost_usd, 0.12)


class TestAutonomousRoe(unittest.TestCase):
    def test_autonomous_note(self):
        proj = {"authorized_by": "x", "window": {"start": "", "end": ""},
                "in_scope": {"domains": ["*.a.com"]}, "out_of_scope": {},
                "rules": {"approval_required_phases": ["exploitation"]}}
        t = roe.render_roe(proj, "eid", autonomous=True)
        self.assertIn("AUTONOMOUS", t)
        self.assertIn("STOP and summarize", t)
        self.assertNotIn("no human is watching", roe.render_roe(proj, "eid", autonomous=False))


if __name__ == "__main__":
    unittest.main()
