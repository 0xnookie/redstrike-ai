#!/usr/bin/env python3
"""Focused tests for the control plane's /api/engagements/audit route (scripts/console_control.py).

Exercises `_audit_engagement` directly (no socket): the authorization/input gate, the
clone+scaffold → resolve-new-id → launch handoff, and the clone-failure surfacing. The redstrike
CLI is stubbed (`_run_cli`) so nothing is cloned or launched; we assert the plane's own wiring."""
import http
import pathlib
import sys
import tempfile
import unittest
from http import HTTPStatus

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import console_control as cc  # noqa: E402


class _FakeProc:
    def __init__(self, rc=0, stdout="", stderr=""):
        self.returncode = rc
        self.stdout = stdout
        self.stderr = stderr
        self.pid = 4242

    def poll(self):
        return None  # "still running" for a backgrounded launch


def _instance(target, token="tok"):
    """A Control handler instance without a socket (bypass __init__), with _json captured."""
    cls = cc.make_control_handler(pathlib.Path(target), token)
    inst = cls.__new__(cls)
    inst._captured = []
    inst._json = lambda status, obj: inst._captured.append((status, obj))  # type: ignore[attr-defined]
    return inst


class TestAuditRoute(unittest.TestCase):
    def tearDown(self):
        cc._RUNS.clear()
        cc._ENDED.clear()

    def _patch_cli(self, target: pathlib.Path, *, audit_rc=0, make_eid="widgets-2026-11-19"):
        calls = []

        def fake(args, *, capture=True, background=False):
            calls.append((list(args), background))
            if args and args[0] == "audit" and not background:
                if audit_rc == 0 and make_eid:
                    # simulate clone+scaffold: a discoverable engagement appears
                    (target / make_eid).mkdir(parents=True, exist_ok=True)
                    (target / make_eid / "scope.yaml").write_text("engagement: x\n", encoding="utf-8")
                return _FakeProc(rc=audit_rc, stdout="ok", stderr="" if audit_rc == 0 else "clone failed: boom")
            return _FakeProc(rc=0)  # background launch (redstrike run)

        return fake, calls

    def test_happy_path_scaffolds_then_launches(self):
        with tempfile.TemporaryDirectory() as d:
            target = pathlib.Path(d)
            fake, calls = self._patch_cli(target)
            orig, cc._run_cli = cc._run_cli, fake
            try:
                inst = _instance(target)
                inst._audit_engagement({
                    "repo_url": "https://example.com/acme/widgets.git",
                    "authorized_by": "appsec@acme / SOW-1",
                    "confirm_authorization": True,
                    "max_turns": 50, "max_budget": 5,
                })
            finally:
                cc._run_cli = orig
            status, body = inst._captured[-1]
            self.assertEqual(status, HTTPStatus.ACCEPTED)         # launched
            self.assertTrue(body["ok"])
            self.assertEqual(body["engagement"], "widgets-2026-11-19")
            # the clone+scaffold call used --no-launch; the second call launched the run
            self.assertIn("--no-launch", calls[0][0])
            self.assertEqual(calls[0][0][0], "audit")
            self.assertEqual(calls[1][0][:3], ["run", "widgets-2026-11-19", "--autonomous"])

    def test_missing_confirm_is_400(self):
        with tempfile.TemporaryDirectory() as d:
            target = pathlib.Path(d)
            inst = _instance(target)
            inst._audit_engagement({"repo_url": "https://x/y.git", "authorized_by": "a"})
            status, body = inst._captured[-1]
            self.assertEqual(status, HTTPStatus.BAD_REQUEST)
            self.assertIn("confirm_authorization", body["error"])

    def test_missing_fields_is_400(self):
        with tempfile.TemporaryDirectory() as d:
            inst = _instance(pathlib.Path(d))
            inst._audit_engagement({"repo_url": "", "authorized_by": "", "confirm_authorization": True})
            status, body = inst._captured[-1]
            self.assertEqual(status, HTTPStatus.BAD_REQUEST)

    def test_clone_failure_surfaces_error_not_200(self):
        with tempfile.TemporaryDirectory() as d:
            target = pathlib.Path(d)
            fake, _calls = self._patch_cli(target, audit_rc=1, make_eid="")
            orig, cc._run_cli = cc._run_cli, fake
            try:
                inst = _instance(target)
                inst._audit_engagement({
                    "repo_url": "https://example.com/acme/widgets.git",
                    "authorized_by": "a", "confirm_authorization": True,
                })
            finally:
                cc._run_cli = orig
            status, body = inst._captured[-1]
            self.assertEqual(status, HTTPStatus.BAD_REQUEST)
            self.assertFalse(body["ok"])
            self.assertIn("clone failed", body["error"])


if __name__ == "__main__":
    unittest.main()
