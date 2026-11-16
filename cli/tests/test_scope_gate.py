import datetime as dt
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # cli/

from redstrike_cli.hooks import scope_gate as sg  # noqa: E402

SCOPE = {
    "in_scope": {"domains": ["*.acme.com", "api.acme.com"], "cidrs": ["203.0.113.0/24"], "urls": []},
    "out_of_scope": {"domains": ["admin.acme.com"], "cidrs": ["203.0.113.200/29"]},
}
CWD = pathlib.Path("/eng")
PROT = [pathlib.Path("/eng/runtime"), pathlib.Path("/eng/scope.yaml")]


def dec(tool, inp, protected=PROT, cwd=CWD):
    return sg.evaluate(tool, inp, SCOPE, protected, cwd)["decision"]


class TestWebFetch(unittest.TestCase):
    def test_in_scope_wildcard(self):
        self.assertEqual(dec("WebFetch", {"url": "https://app.acme.com/x"}), "pass")

    def test_in_scope_exact(self):
        self.assertEqual(dec("WebFetch", {"url": "https://api.acme.com/v1"}), "pass")

    def test_out_of_scope_exclude(self):
        self.assertEqual(dec("WebFetch", {"url": "https://admin.acme.com/"}), "deny")

    def test_unknown_host(self):
        self.assertEqual(dec("WebFetch", {"url": "https://evil.example-attacker.com/"}), "deny")

    def test_localhost_ignorable(self):
        self.assertEqual(dec("WebFetch", {"url": "http://localhost:8080/"}), "pass")

    # schemeless / bare-hostname URLs must not fail OPEN past the gate
    def test_schemeless_out_of_scope(self):
        self.assertEqual(dec("WebFetch", {"url": "admin.acme.com/panel"}), "deny")

    def test_schemeless_unknown_host(self):
        self.assertEqual(dec("WebFetch", {"url": "evil.example-attacker.com/x"}), "deny")
        self.assertEqual(dec("WebFetch", {"url": "evil.example-attacker.com"}), "deny")

    def test_schemeless_in_scope_passes(self):
        self.assertEqual(dec("WebFetch", {"url": "app.acme.com/x"}), "pass")

    def test_schemeless_localhost_ignorable(self):
        self.assertEqual(dec("WebFetch", {"url": "localhost:8080/x"}), "pass")

    def test_path_only_no_host_passes(self):
        self.assertEqual(dec("WebFetch", {"url": "/local/only/path"}), "pass")


class TestBash(unittest.TestCase):
    def test_in_scope_host(self):
        self.assertEqual(dec("Bash", {"command": "nmap -sV api.acme.com"}), "pass")

    def test_out_of_scope_host(self):
        self.assertEqual(dec("Bash", {"command": "nmap admin.acme.com"}), "deny")

    def test_unknown_external(self):
        self.assertEqual(dec("Bash", {"command": "curl https://evil-corp-attacker.com/x"}), "deny")

    def test_in_scope_cidr_ip(self):
        self.assertEqual(dec("Bash", {"command": "nmap 203.0.113.5"}), "pass")

    def test_out_of_scope_cidr_ip(self):
        self.assertEqual(dec("Bash", {"command": "nmap 203.0.113.201"}), "deny")

    def test_loopback_ip(self):
        self.assertEqual(dec("Bash", {"command": "curl http://127.0.0.1:9000/"}), "pass")

    def test_no_targets(self):
        self.assertEqual(dec("Bash", {"command": "ls -la ./evidence"}), "pass")


class TestWriteGuard(unittest.TestCase):
    def test_protected_and_allowed_paths(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d)
            (eng / "runtime").mkdir()
            scope_json = eng / "runtime" / "scope.json"
            scope_json.write_text("{}", encoding="utf-8")
            prot = sg.protected_paths(scope_json)

            def wdec(path):
                return sg.evaluate("Write", {"file_path": path}, SCOPE, prot, eng)["decision"]

            self.assertEqual(wdec(str(eng / "runtime" / "settings.json")), "deny")
            self.assertEqual(wdec("runtime/scope.json"), "deny")  # relative to cwd=eng
            self.assertEqual(wdec(str(eng / "scope.yaml")), "deny")
            self.assertEqual(wdec(str(eng / "findings" / "evidence" / "x.txt")), "pass")


class TestFilenameNotHost(unittest.TestCase):
    """A dotted filename in a shell command must NOT be read as an out-of-scope host.
    Regression: `scope.json` / `homepage.html` / `*.py` were classified as hosts, so the gate
    denied the agent reading its own files and saving tool output (`curl ... -o out.html`),
    stalling autonomous runs."""

    def test_extract_skips_file_extensions(self):
        self.assertEqual(sg.extract_targets("cat runtime/scope.json runtime/authorization.json"), [])
        self.assertEqual(sg.extract_targets("nmap -oN scan.txt; cat out.json report.md"), [])
        self.assertEqual(sg.extract_targets("grep -rl x --include=*.py --include=*.sh ."), [])

    def test_extract_keeps_real_hosts_alongside_files(self):
        # a scheme'd target is still extracted even when the path looks file-ish
        self.assertEqual(sg.extract_targets("curl https://evil.example-attacker.com/a.json -o x.json"),
                         ["evil.example-attacker.com"])

    def test_read_own_governance_files_passes(self):
        self.assertEqual(dec("Bash", {"command": "cat runtime/scope.json runtime/authorization.json"}), "pass")

    def test_save_localhost_output_to_html_passes(self):
        # the live-run failure: localhost is ignorable, homepage.html must not be a "host"
        self.assertEqual(
            dec("Bash", {"command": "curl -s http://localhost:8080/ -o osint/logs/homepage.html"}), "pass")

    def test_grep_include_globs_pass(self):
        self.assertEqual(dec("Bash", {"command": "grep -rl scope-gate --include=*.py --include=*.json ."}), "pass")

    def test_out_of_scope_host_still_denied_with_file_args(self):
        # the fix must not let a real out-of-scope host slip through just because a file is nearby
        self.assertEqual(dec("Bash", {"command": "nmap admin.acme.com -oN scan.txt"}), "deny")
        self.assertEqual(dec("Bash", {"command": "curl https://evil-corp-attacker.com/x -o loot.json"}), "deny")


class TestCodeIdentifierNotHost(unittest.TestCase):
    """A dotted code attribute/method call (json.load, d.get, subprocess.run) must NOT be read
    as a host. Regression: inline python/js in a Bash command (json.load(open('x.json'))) was
    denied because `json.load` matched the bare-host regex."""

    def test_extract_skips_method_calls(self):
        self.assertEqual(sg.extract_targets("d=json.load(open('coverage_ledger.json'))"), [])
        self.assertEqual(sg.extract_targets("cats=d.get('categories') or d.get('coverage')"), [])
        self.assertEqual(sg.extract_targets("subprocess.run(['ls']); os.path.join(a,b)"), [])

    def test_inline_python_reading_ledger_passes(self):
        cmd = "python3 -c \"import json; print(json.load(open('coverage_ledger.json')).get('x'))\""
        self.assertEqual(dec("Bash", {"command": cmd}), "pass")

    def test_real_host_not_followed_by_paren_still_classified(self):
        # the "(" rule must not swallow a genuine out-of-scope host
        self.assertEqual(sg.extract_targets("curl admin.acme.com/panel"), ["admin.acme.com"])
        self.assertEqual(dec("Bash", {"command": "nmap admin.acme.com"}), "deny")


class TestEngagementWindow(unittest.TestCase):
    """The engagement window is re-checked on every active tool call, not just at launch:
    once now > window.end (or before window.start) active tooling is DENIED, fail-closed."""

    WIN_SCOPE = {
        "in_scope": {"domains": ["*.acme.com"], "cidrs": [], "urls": []},
        "out_of_scope": {"domains": [], "cidrs": []},
        "window": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-31T23:59:59Z"},
    }
    BEFORE = dt.datetime(2025, 12, 1, tzinfo=dt.timezone.utc)
    DURING = dt.datetime(2026, 1, 15, tzinfo=dt.timezone.utc)
    AFTER = dt.datetime(2026, 2, 15, tzinfo=dt.timezone.utc)

    def _d(self, tool, inp, now):
        return sg.evaluate(tool, inp, self.WIN_SCOPE, PROT, CWD, now=now)

    def test_bash_denied_after_window_closes(self):
        out = self._d("Bash", {"command": "nmap app.acme.com"}, self.AFTER)
        self.assertEqual(out["decision"], "deny")
        self.assertIn("window has closed", out["reason"])

    def test_webfetch_denied_after_window_closes(self):
        self.assertEqual(self._d("WebFetch", {"url": "https://app.acme.com/"}, self.AFTER)["decision"], "deny")

    def test_mcp_denied_after_window_closes(self):
        out = sg.evaluate("mcp__x__browser", {"args": ["https://app.acme.com/"]},
                          self.WIN_SCOPE, PROT, CWD, now=self.AFTER)
        self.assertEqual(out["decision"], "deny")

    def test_denied_before_window_opens(self):
        out = self._d("Bash", {"command": "nmap app.acme.com"}, self.BEFORE)
        self.assertEqual(out["decision"], "deny")
        self.assertIn("not opened yet", out["reason"])

    def test_in_window_in_scope_passes(self):
        self.assertEqual(self._d("Bash", {"command": "nmap app.acme.com"}, self.DURING)["decision"], "pass")

    def test_out_of_scope_still_denied_in_window(self):
        # window being open does not loosen scope enforcement
        out = sg.evaluate("WebFetch", {"url": "https://evil-attacker-xyz.com/"},
                          self.WIN_SCOPE, PROT, CWD, now=self.DURING)
        self.assertEqual(out["decision"], "deny")

    def test_local_write_not_blocked_by_closed_window(self):
        # findings/notes can still be written up after the window closes (write-guard only)
        out = sg.evaluate("Write", {"file_path": str(CWD / "findings" / "report.md")},
                          self.WIN_SCOPE, PROT, CWD, now=self.AFTER)
        self.assertEqual(out["decision"], "pass")

    def test_no_window_key_is_not_denied(self):
        # a scope with no window (the other fixtures) must behave as before
        self.assertEqual(sg.evaluate("Bash", {"command": "nmap api.acme.com"}, SCOPE, PROT, CWD,
                                     now=self.AFTER)["decision"], "pass")


class TestEvaluateContract(unittest.TestCase):
    def test_deny_has_reason(self):
        out = sg.evaluate("WebFetch", {"url": "https://admin.acme.com/"}, SCOPE, PROT, CWD)
        self.assertEqual(out["decision"], "deny")
        self.assertTrue(out["reason"])


class TestMcpGate(unittest.TestCase):
    """MCP tool calls are scanned for out-of-scope targets in their free-form input."""

    def mdec(self, args):
        return sg.evaluate("mcp__interceptor__browser", {"verb": "browser", "args": args},
                           SCOPE, PROT, CWD)["decision"]

    def test_in_scope_url(self):
        self.assertEqual(self.mdec(["open", "https://app.acme.com/x"]), "pass")

    def test_out_of_scope_url(self):
        self.assertEqual(self.mdec(["open", "https://admin.acme.com/"]), "deny")

    def test_unknown_external_url(self):
        self.assertEqual(self.mdec(["open", "https://evil-attacker-xyz.com/"]), "deny")

    def test_no_host_action_passes(self):
        # already-attached-tab action carries no host → gate can't see it (documented blind spot)
        self.assertEqual(self.mdec(["click", "role:button[name=Submit]"]), "pass")


class TestAlwaysDeferExploitTokens(unittest.TestCase):
    """Active-exploit tokens DEFER even under a broad `Bash` / `*` allow, so unattended
    exploitation still reaches the operator — unless the operator pre-allowed that exact tool
    with a narrow glob, or approved the exact command. DENY still takes precedence."""

    ALWAYS = frozenset({"sqlmap", "msfconsole", "hydra"})

    def _d(self, cmd, **kw):
        return sg.evaluate("Bash", {"command": cmd}, SCOPE, PROT, CWD, **kw)["decision"]

    def test_exploit_token_defers_under_blanket_allow(self):
        # broad `Bash` → bash_allow=["*"]; sqlmap against an in-scope host must still DEFER
        self.assertEqual(
            self._d("sqlmap -u https://app.acme.com/x --batch", defer=True,
                    bash_allow=["*"], always_defer=self.ALWAYS),
            "defer",
        )

    def test_narrow_preallow_of_exploit_token_passes(self):
        # operator explicitly pre-allowed this exact tool → escape hatch, PASS
        self.assertEqual(
            self._d("sqlmap -u https://app.acme.com/x --batch", defer=True,
                    bash_allow=["sqlmap *"], always_defer=self.ALWAYS),
            "pass",
        )

    def test_approved_exact_command_passes_despite_always_defer(self):
        cmd = "sqlmap -u https://app.acme.com/x --batch"
        fp = sg.fingerprint("Bash", {"command": cmd})
        self.assertEqual(
            self._d(cmd, defer=True, bash_allow=["*"], always_defer=self.ALWAYS,
                    approvals=frozenset([fp])),
            "pass",
        )

    def test_ordinary_tool_under_blanket_allow_passes(self):
        # a non-exploit tool under `*` is unaffected — it runs
        self.assertEqual(
            self._d("nmap -sV api.acme.com", defer=True, bash_allow=["*"], always_defer=self.ALWAYS),
            "pass",
        )

    def test_blanket_allow_is_not_a_narrow_preallow(self):
        # the bare `*` must NOT count as naming the exploit tool
        self.assertEqual(
            self._d("hydra -l admin -P list.txt api.acme.com ssh", defer=True,
                    bash_allow=["*"], always_defer=self.ALWAYS),
            "defer",
        )

    def test_out_of_scope_host_still_denies_even_for_exploit_token(self):
        # DENY precedence: out-of-scope wins over the always-defer branch
        self.assertEqual(
            self._d("sqlmap -u https://admin.acme.com/x", defer=True,
                    bash_allow=["sqlmap *"], always_defer=self.ALWAYS),
            "deny",
        )

    def test_empty_always_defer_is_back_compat(self):
        # no always-defer set → broad allow runs the exploit tool as before
        self.assertEqual(
            self._d("sqlmap -u https://app.acme.com/x", defer=True, bash_allow=["*"]),
            "pass",
        )


class TestEmitDeferMessage(unittest.TestCase):
    """The defer message must tell the agent to CONTINUE, not stop the whole run."""

    def test_defer_message_says_continue_not_stop(self):
        import io
        import contextlib

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            sg._emit_defer("shell command needs operator approval: sqlmap -u x")
        out = buf.getvalue().lower()
        self.assertIn("continue", out)
        self.assertNotIn("summarize and stop", out)
        self.assertNotIn("stop", out)  # no "stop" wording at all


class TestPortScopedDomain(unittest.TestCase):
    """A scope authored as "host:port" must still match the (always port-less) target host —
    otherwise the whole host is silently out of scope and every active command is denied."""

    PORT_SCOPE = {
        "in_scope": {"domains": ["pentest-ground.com:4280"], "cidrs": [], "urls": []},
        "out_of_scope": {"domains": [], "cidrs": []},
    }

    def pdec(self, tool, inp):
        return sg.evaluate(tool, inp, self.PORT_SCOPE, PROT, CWD)["decision"]

    def test_classify_host_in_scope(self):
        self.assertEqual(sg.classify("pentest-ground.com", self.PORT_SCOPE), "in")
        self.assertEqual(sg.classify("pentest-ground.com:4280", self.PORT_SCOPE), "in")

    def test_bash_against_port_scoped_host_passes(self):
        self.assertEqual(self.pdec("Bash", {"command": "curl -sS http://pentest-ground.com:4280/"}), "pass")

    def test_webfetch_against_port_scoped_host_passes(self):
        self.assertEqual(self.pdec("WebFetch", {"url": "http://pentest-ground.com:4280/"}), "pass")

    def test_other_host_still_unknown(self):
        self.assertEqual(sg.classify("elsewhere.com", self.PORT_SCOPE), "unknown")


if __name__ == "__main__":
    unittest.main()
