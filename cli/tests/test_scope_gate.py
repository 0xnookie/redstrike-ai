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


if __name__ == "__main__":
    unittest.main()
