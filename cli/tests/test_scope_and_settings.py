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
