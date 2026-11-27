import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # cli/

from redstrike_cli import approvals, autorun, engagement, launch, roe, settings  # noqa: E402
from redstrike_cli.hooks import scope_gate as sg  # noqa: E402


class TestAutonomousSettings(unittest.TestCase):
    def test_allowlist_and_bash_globs(self):
        base = settings.autonomous_allowlist()
        self.assertIn("WebFetch", base)
        self.assertIn("Bash", base)  # broad, but hook-gated (defers un-approved shell)
        self.assertEqual(settings.bash_allow_globs(["Bash(nmap *)", "WebFetch"]), ["nmap *"])
        self.assertEqual(settings.bash_allow_globs(["Bash"]), ["*"])
        self.assertEqual(settings.bash_allow_globs([]), [])

    def test_broad_allow_warnings(self):
        # bare Bash / wildcard glob → runs anything with no deferral
        self.assertTrue(settings.broad_allow_warnings(["Bash"]))
        self.assertTrue(settings.broad_allow_warnings(["Bash(*)"]))
        # an active-exploit tool pre-allow is flagged
        w = settings.broad_allow_warnings(["Bash(sqlmap --dump *)"])
        self.assertEqual(len(w), 1)
        self.assertIn("sqlmap", w[0])
        # a leading-wildcard glob is broad
        self.assertTrue(settings.broad_allow_warnings(["Bash(* --batch)"]))
        # a narrow recon pre-allow is NOT flagged
        self.assertEqual(settings.broad_allow_warnings(["Bash(nmap *)", "WebFetch"]), [])
        self.assertEqual(settings.broad_allow_warnings([]), [])

    def test_render_settings_mode_wires_defer(self):
        s = settings.render_settings(
            python_exe="py", hook_script=pathlib.Path("/h.py"), scope_json=pathlib.Path("/s.json"),
            mode="autonomous", gate_policy=pathlib.Path("/p.json"), approvals=pathlib.Path("/a.json"),
        )
        self.assertIn("WebFetch", s["permissions"]["allow"])
        self.assertIn("Bash", s["permissions"]["allow"])
        cmd = s["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.assertIn("--defer", cmd)
        self.assertIn("--policy", cmd)
        self.assertIn("--approvals", cmd)
        si = settings.render_settings(
            python_exe="py", hook_script=pathlib.Path("/h.py"), scope_json=pathlib.Path("/s.json"),
        )
        self.assertNotIn("WebFetch", si["permissions"]["allow"])  # interactive stays read-only
        self.assertNotIn("--defer", si["hooks"]["PreToolUse"][0]["hooks"][0]["command"])


_SCOPE = {"in_scope": {"domains": ["*.a.com"], "cidrs": [], "urls": []}, "out_of_scope": {"domains": [], "cidrs": []}}
_PROT = [pathlib.Path("/eng/runtime"), pathlib.Path("/eng/scope.yaml")]


class TestDeferGate(unittest.TestCase):
    def _d(self, cmd, **kw):
        return sg.evaluate("Bash", {"command": cmd}, _SCOPE, _PROT, pathlib.Path("/eng"), **kw)["decision"]

    def test_unapproved_shell_defers(self):
        self.assertEqual(self._d("echo hi", defer=True), "defer")

    def test_pre_allowed_glob_passes(self):
        self.assertEqual(self._d("nmap -sV a.com", defer=True, bash_allow=["nmap *"]), "pass")

    def test_approved_fingerprint_passes(self):
        fp = sg.fingerprint("Bash", {"command": "echo hi"})
        self.assertEqual(self._d("echo hi", defer=True, approvals=frozenset([fp])), "pass")

    def test_out_of_scope_denies_even_in_defer(self):
        self.assertEqual(self._d("curl https://evil-x.example-attacker.com/", defer=True), "deny")

    def test_no_defer_mode_passes(self):
        self.assertEqual(self._d("echo hi"), "pass")  # interactive: not deferred


class TestAutonomousArgv(unittest.TestCase):
    def test_argv_shape(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            fields = engagement.build_fields(client="Acme", authorized_by="s", domains=["*.a.com"])
            engagement.scaffold(repo, fields, operator="t")
            eng = repo / "engagements" / fields["engagement"]
            prep = launch.prepare_runtime(eng, repo, "py", mode="autonomous", extra_allow=["Bash(nmap *)"])
            self.assertTrue((eng / "runtime" / "gate-policy.json").is_file())
            self.assertTrue((eng / "runtime" / "approvals.json").is_file())
            self.assertTrue(prep.pending_path.name == "approvals_pending.json")
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

    def test_tool_result_errors_counted(self):
        s = autorun.RunSummary()
        buf = io.StringIO()
        # an assistant tool_use establishes the id->name correlation
        autorun.handle_event(
            {"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": "tu_1", "name": "Bash", "input": {"command": "ffuf ..."}}]}},
            s, buf,
        )
        # a failed tool_result (is_error) for that id is counted against the tool name
        autorun.handle_event(
            {"type": "user", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "tu_1", "is_error": True, "content": "boom"}]}},
            s, buf,
        )
        # a successful tool_result is NOT counted
        autorun.handle_event(
            {"type": "user", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "tu_1", "is_error": False}]}},
            s, buf,
        )
        self.assertEqual(s.tool_failures, [{"tool": "Bash", "exit_code": None, "phase": None, "count": 1}])

    def test_non_json_line_counting(self):
        import pathlib as _pl
        import tempfile as _tf
        # drive run_autonomous against a fake "claude" that emits a mix of JSON and chatty lines
        with _tf.TemporaryDirectory() as d:
            d = _pl.Path(d)
            script = d / "fake.py"
            script.write_text(
                "import sys\n"
                "print('a stray warning line')\n"
                "print('{\"type\": \"result\", \"subtype\": \"success\"}')\n"
                "print('another non-json line')\n"
            )
            argv = [sys.executable, str(script)]
            rc, s = autorun.run_autonomous(sys.executable, argv, d, d / "audit.jsonl", stream=io.StringIO())
            self.assertEqual(rc, 0)
            self.assertEqual(s.non_json_lines, 2)
            self.assertEqual(s.non_json_sample, "a stray warning line")


class _FakeProc:
    """A mock Popen for the interrupt-teardown path. In `hang` mode the first bounded wait times out
    (modelling a `claude -p` leg that ignores the polite terminate), forcing a hard kill."""

    def __init__(self, *, exits_within_grace=False, pid=4321):
        self.pid = pid
        self.returncode = 0 if exits_within_grace else None
        self._exits_within_grace = exits_within_grace
        self.killed = False
        self.terminated = False
        self.signals = []

    def send_signal(self, sig):
        self.signals.append(sig)

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        if self._exits_within_grace or self.killed:
            return self.returncode
        raise subprocess.TimeoutExpired(cmd="claude", timeout=timeout)


class TestInterruptTeardown(unittest.TestCase):
    def test_bounded_wait_then_hard_kill(self):
        # A leg that ignores the polite terminate (wait times out) must be HARD-killed, not waited on
        # forever — and the returncode still comes back.
        proc = _FakeProc()
        rc = autorun._terminate_proc_group(proc, stream=io.StringIO(), grace=0.01)
        self.assertTrue(proc.killed)
        self.assertEqual(rc, -9)

    def test_clean_exit_within_grace_no_kill(self):
        # A leg that honours the terminate within the grace window is NOT hard-killed.
        proc = _FakeProc(exits_within_grace=True)
        rc = autorun._terminate_proc_group(proc, stream=io.StringIO(), grace=0.01)
        self.assertFalse(proc.killed)
        self.assertEqual(rc, 0)


class TestAutonomousRoe(unittest.TestCase):
    def test_autonomous_note(self):
        proj = {"authorized_by": "x", "window": {"start": "", "end": ""},
                "in_scope": {"domains": ["*.a.com"]}, "out_of_scope": {},
                "rules": {"approval_required_phases": ["exploitation"]}}
        t = roe.render_roe(proj, "eid", autonomous=True)
        self.assertIn("AUTONOMOUS", t)
        self.assertIn("HARD STOP", t)
        self.assertIn("deferred for operator approval", t)
        self.assertNotIn("deferred for operator approval", roe.render_roe(proj, "eid", autonomous=False))


class TestApprovals(unittest.TestCase):
    def test_pending_approve_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            ap_path = pathlib.Path(d) / "approvals.json"
            pend_path = pathlib.Path(d) / "pending.json"
            approvals.ensure_files(ap_path, pend_path)
            deferred = [{"id": "t1", "name": "Bash", "input": {"command": "nmap -sV a.com"}}]
            self.assertEqual(approvals.record_deferred(pend_path, deferred), 1)
            self.assertEqual(approvals.record_deferred(pend_path, deferred), 0)  # dedupe
            pend = approvals.list_pending(pend_path)
            self.assertEqual(len(pend), 1)
            fp = pend[0]["fingerprint"]
            self.assertEqual(fp, sg.fingerprint("Bash", {"command": "nmap -sV a.com"}))  # matches hook
            moved = approvals.approve(ap_path, pend_path, [fp])
            self.assertEqual(len(moved), 1)
            self.assertEqual(approvals.list_pending(pend_path), [])
            self.assertIn(fp, json.loads(ap_path.read_text(encoding="utf-8"))["approved"])


if __name__ == "__main__":
    unittest.main()
