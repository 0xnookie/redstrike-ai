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
