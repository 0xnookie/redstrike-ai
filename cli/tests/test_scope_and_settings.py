import datetime as dt
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # cli/

from redstrike_cli import roe, scope, settings  # noqa: E402


class TestScope(unittest.TestCase):
    def test_build_projection_normalizes_datetime(self):
        raw = {
            "engagement": "acme-2026-10-19",
            "authorized_by": "sec@acme",
            "window": {
                "start": dt.datetime(2026, 10, 16, tzinfo=dt.timezone.utc),
                "end": dt.datetime(2026, 10, 30, 23, 59, 59, tzinfo=dt.timezone.utc),
            },
            "in_scope": {"domains": ["*.acme.com"], "cidrs": [], "urls": []},
            "out_of_scope": {"domains": [], "cidrs": []},
            "rules": {"rate_limit_rps": 20, "approval_required_phases": ["exploitation"]},
        }
        proj = scope.build_projection(raw)
        self.assertEqual(proj["window"]["start"], "2026-10-16T00:00:00Z")
        self.assertEqual(proj["in_scope"]["domains"], ["*.acme.com"])
        json.dumps(proj)  # must be serializable

    def test_window_open(self):
        now = dt.datetime(2026, 10, 20, tzinfo=dt.timezone.utc)
        s = {"window": {"start": "2026-10-16T00:00:00Z", "end": "2026-10-30T23:59:59Z"}}
        self.assertTrue(scope.window_open(s, now=now)[0])
        closed = {"window": {"start": "2026-10-16T00:00:00Z", "end": "2026-10-18T00:00:00Z"}}
        self.assertFalse(scope.window_open(closed, now=now)[0])

    def test_is_complete(self):
        bad = {"authorized_by": "<fill me>", "in_scope": {}, "window": {}}
        self.assertFalse(scope.is_complete(bad)[0])
        good = {
            "authorized_by": "sec@acme",
            "in_scope": {"domains": ["*.acme.com"]},
            "window": {"start": "2026-10-16T00:00:00Z", "end": "2026-10-30T23:59:59Z"},
        }
        self.assertTrue(scope.is_complete(good)[0])


class TestSettings(unittest.TestCase):
    def test_render_settings(self):
        s = settings.render_settings(
            python_exe="/usr/bin/python3",
            hook_script=pathlib.Path("/repo/cli/redstrike_cli/hooks/scope_gate.py"),
            scope_json=pathlib.Path("/eng/runtime/scope.json"),
        )
        json.dumps(s)  # valid
        hook = s["hooks"]["PreToolUse"][0]
        self.assertIn("Bash", hook["matcher"])
        cmd = hook["hooks"][0]["command"]
        self.assertIn("scope_gate.py", cmd)
        self.assertIn("--scope", cmd)
        self.assertTrue(any("runtime/**" in r for r in s["permissions"]["deny"]))
        self.assertEqual(
            s["env"]["REDSTRIKE_SCOPE_FILE"], str(pathlib.Path("/eng/runtime/scope.json"))
        )
        self.assertNotIn("Bash", s["permissions"]["allow"])  # offensive stays interactive

    def test_rate_gate_wired(self):
        s = settings.render_settings(
            python_exe="/usr/bin/python3",
            hook_script=pathlib.Path("/repo/cli/redstrike_cli/hooks/scope_gate.py"),
            scope_json=pathlib.Path("/eng/runtime/scope.json"),
        )
        pre = s["hooks"]["PreToolUse"][0]["hooks"]
        # scope gate first (fails closed), rate gate second (fails open)
        self.assertIn("scope_gate.py", pre[0]["command"])
        self.assertIn("rate_gate.py", pre[1]["command"])
        self.assertIn("--state", pre[1]["command"])
        self.assertNotIn("--observe", pre[1]["command"])
        # PostToolUse runs the rate gate in observe mode to feed the breaker
        post = s["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
        self.assertIn("rate_gate.py", post)
        self.assertIn("--observe", post)
        self.assertEqual(
            s["env"]["REDSTRIKE_RATE_STATE"], str(pathlib.Path("/eng/runtime/rate_state.json"))
        )

    def test_max_rps_clamp_rendered(self):
        s = settings.render_settings(
            python_exe="/usr/bin/python3",
            hook_script=pathlib.Path("/repo/cli/redstrike_cli/hooks/scope_gate.py"),
            scope_json=pathlib.Path("/eng/runtime/scope.json"),
            max_rps=3,
        )
        self.assertIn("--max-rps", s["hooks"]["PreToolUse"][0]["hooks"][1]["command"])

    def test_no_sandbox_block_without_scope(self):
        # the existing callers pass no scope → no sandbox key (nothing to derive it from)
        s = settings.render_settings(
            python_exe="/usr/bin/python3",
            hook_script=pathlib.Path("/repo/cli/redstrike_cli/hooks/scope_gate.py"),
            scope_json=pathlib.Path("/eng/runtime/scope.json"),
        )
        self.assertNotIn("sandbox", s)


class TestSandbox(unittest.TestCase):
    SCOPE = {
        "in_scope": {
            "domains": ["*.acme.com", "API.acme.com"],
            "cidrs": ["203.0.113.0/24"],
            "urls": ["https://portal.acme.com/login"],
        },
        "out_of_scope": {"domains": ["admin.acme.com"], "cidrs": ["203.0.113.200/29"]},
    }

    def test_build_sandbox_from_scope(self):
        sb = settings.build_sandbox(self.SCOPE)
        self.assertIsNotNone(sb)
        # the sandbox must actually be turned on — without `enabled` the whole block is inert
        self.assertIs(sb["enabled"], True)
        net = sb["network"]
        # a host outside the allowlist must be a hard DENY, not just a prompt
        self.assertIs(net["strictAllowlist"], True)
        # correct schema key is allowedDomains (NOT allowedHosts, which Claude Code drops)
        self.assertNotIn("allowedHosts", net)
        domains = net["allowedDomains"]
        # domains + cidrs + the host extracted from in_scope.urls, lowercased + deduped
        self.assertIn("*.acme.com", domains)
        self.assertIn("api.acme.com", domains)        # normalized to lowercase
        self.assertIn("203.0.113.0/24", domains)
        self.assertIn("portal.acme.com", domains)     # from the url entry
        self.assertIn("allowUnixSockets", net)

    def test_engine_hosts_always_allowlisted(self):
        # the engine's own control-plane host is present regardless of (even minimal) scope
        minimal = {"in_scope": {"domains": ["acme.com"]}, "out_of_scope": {}}
        domains = settings.build_sandbox(minimal)["network"]["allowedDomains"]
        self.assertIn("api.anthropic.com", domains)
        self.assertIn("acme.com", domains)
        # engine hosts come first, ahead of the scope-derived entries
        self.assertLess(domains.index("api.anthropic.com"), domains.index("acme.com"))

    def test_explicit_out_of_scope_entries_excluded(self):
        # an entry that is itself explicitly out-of-scope never lands on the allowlist
        scope = {
            "in_scope": {"domains": ["acme.com", "admin.acme.com"], "cidrs": [], "urls": []},
            "out_of_scope": {"domains": ["admin.acme.com"], "cidrs": []},
        }
        domains = settings.build_sandbox(scope)["network"]["allowedDomains"]
        self.assertIn("acme.com", domains)
        self.assertNotIn("admin.acme.com", domains)

    def test_build_sandbox_none_without_scope(self):
        self.assertIsNone(settings.build_sandbox(None))
        self.assertIsNone(settings.build_sandbox({}))

    def test_render_settings_emits_sandbox_from_scope(self):
        s = settings.render_settings(
            python_exe="/usr/bin/python3",
            hook_script=pathlib.Path("/repo/cli/redstrike_cli/hooks/scope_gate.py"),
            scope_json=pathlib.Path("/eng/runtime/scope.json"),
            scope=self.SCOPE,
        )
        json.dumps(s)  # serializable
        self.assertIn("sandbox", s)
        self.assertIs(s["sandbox"]["enabled"], True)
        net = s["sandbox"]["network"]
        self.assertIn("*.acme.com", net["allowedDomains"])
        self.assertIn("api.anthropic.com", net["allowedDomains"])
        self.assertNotIn("admin.acme.com", net["allowedDomains"])


class TestRoe(unittest.TestCase):
    def test_roe_contains_key_directives(self):
        proj = {
            "authorized_by": "sec@acme",
            "window": {"start": "2026-10-16T00:00:00Z", "end": "2026-10-30T23:59:59Z"},
            "in_scope": {"domains": ["*.acme.com"], "cidrs": [], "urls": []},
            "out_of_scope": {"domains": ["admin.acme.com"], "cidrs": []},
            "rules": {"no_dos": True, "rate_limit_rps": 20, "approval_required_phases": ["exploitation"]},
        }
        text = roe.render_roe(proj, "acme-2026-10-19")
        self.assertIn("SATISFIED", text)
        self.assertIn("HARD STOP", text)
        self.assertIn("scope gate", text)
        self.assertIn("*.acme.com", text)
        self.assertIn("admin.acme.com", text)


if __name__ == "__main__":
    unittest.main()
