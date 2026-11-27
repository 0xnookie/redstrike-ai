#!/usr/bin/env python3
"""Regression test for the control plane's run-launch TOCTOU race (scripts/console_control.py).

`_run_engagement` must make its guard -> spawn -> register sequence ATOMIC under a single held
`_RUNS_LOCK`. Before the fix the lock was released between the "is a run already live?" check and
the spawn+register, so two near-simultaneous POST /api/engagements/<id>/run for the SAME eid (a
double-click) could both pass the guard and both launch an autonomous `redstrike run` — two
concurrent runs on one target, and the first process left untracked (so /stop and /delete could
never kill it).

These tests drive `_run_engagement` directly (no socket): `_run_cli` — the module-level spawn the
handler calls — is stubbed with a fake that BLOCKS inside the spawn, letting us (1) prove the lock
is held ACROSS the spawn and (2) run two concurrent callers and assert only one launches."""
import pathlib
import sys
import threading
import unittest
from http import HTTPStatus

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import console_control as cc  # noqa: E402

EID = "race-target-2026-11-27"


class _FakeProc:
    """A backgrounded-launch stand-in: poll() is None ("still running") + a distinct pid."""
    def __init__(self, pid):
        self.pid = pid

    def poll(self):
        return None


def _instance(token="tok"):
    """A Control handler instance without a socket (bypass __init__), with _json captured.

    `_run_engagement` only ever touches `self._json`, so a stub that records (status, obj) is
    enough to observe what each caller returned."""
    cls = cc.make_control_handler(pathlib.Path("."), token)
    inst = cls.__new__(cls)
    inst._captured = []
    inst._json = lambda status, obj: inst._captured.append((status, obj))  # type: ignore[attr-defined]
    return inst


class TestRunEngagementRace(unittest.TestCase):
    def setUp(self):
        self._orig_run_cli = cc._run_cli
        cc._RUNS.clear()
        cc._ENDED.clear()

    def tearDown(self):
        cc._run_cli = self._orig_run_cli
        cc._RUNS.clear()
        cc._ENDED.clear()

    def _blocking_cli(self):
        """A fake _run_cli that records each (real) spawn and blocks inside the spawn until
        released — modelling the window the race lives in. Returns a fresh _FakeProc per call."""
        state = {"calls": 0, "entered": threading.Event(), "release": threading.Event(),
                 "lock": threading.Lock()}

        def fake(args, *, capture=True, background=False):
            with state["lock"]:
                state["calls"] += 1
                pid = 9000 + state["calls"]
            state["entered"].set()        # signal: a spawn is in progress
            state["release"].wait(5)       # hold here so a concurrent caller can contend
            return _FakeProc(pid)

        return fake, state

    def test_lock_is_held_across_the_spawn(self):
        """Direct proof of the fix: while a caller is inside the (blocking) spawn, `_RUNS_LOCK`
        is HELD — i.e. the guard, spawn and register are one atomic critical section. Under the
        old check-then-release-then-spawn structure the lock would be free here."""
        fake, state = self._blocking_cli()
        cc._run_cli = fake
        inst = _instance()

        t = threading.Thread(target=inst._run_engagement, args=(EID, {}), daemon=True)
        t.start()
        try:
            self.assertTrue(state["entered"].wait(5), "spawn was never entered")
            # The caller is parked INSIDE _run_cli. If check->spawn->register is atomic, it still
            # holds _RUNS_LOCK right now, so a non-blocking acquire must FAIL.
            got = cc._RUNS_LOCK.acquire(blocking=False)
            if got:
                cc._RUNS_LOCK.release()
            self.assertFalse(
                got, "_RUNS_LOCK was free during the spawn — check->spawn->register is NOT atomic")
        finally:
            state["release"].set()
            t.join(5)
        self.assertFalse(t.is_alive(), "launch thread did not finish")
        self.assertEqual(state["calls"], 1)

    def test_two_concurrent_runs_launch_only_once(self):
        """Two concurrent `_run_engagement` calls for the SAME eid: exactly ONE real spawn, one
        202/ACCEPTED, one 409/CONFLICT, and `_RUNS[eid]` tracks the single live proc."""
        fake, state = self._blocking_cli()
        cc._run_cli = fake
        # Pre-seed how the last run ended, to prove the fresh launch clears it (_ENDED.pop).
        cc._ENDED[EID] = {"how": "stopped"}

        inst_a, inst_b = _instance(), _instance()

        def call(inst):
            inst._run_engagement(EID, {})

        ta = threading.Thread(target=call, args=(inst_a,), daemon=True)
        tb = threading.Thread(target=call, args=(inst_b,), daemon=True)

        ta.start()
        # Wait until A is parked inside the spawn holding the lock, THEN start B so B must contend
        # for _RUNS_LOCK (it will block until A registers and releases).
        self.assertTrue(state["entered"].wait(5), "first caller never entered the spawn")
        tb.start()
        state["release"].set()
        ta.join(5)
        tb.join(5)
        self.assertFalse(ta.is_alive() or tb.is_alive(), "a caller thread hung")

        # Exactly one real spawn happened despite two concurrent callers.
        self.assertEqual(state["calls"], 1, "the race spawned more than one run")

        results = inst_a._captured + inst_b._captured
        self.assertEqual(len(results), 2, "each caller should have produced exactly one response")
        statuses = sorted(s for s, _ in results)
        self.assertEqual(statuses, [HTTPStatus.ACCEPTED, HTTPStatus.CONFLICT],
                         "expected one 202 ACCEPTED and one 409 CONFLICT")

        accepted = next(obj for s, obj in results if s == HTTPStatus.ACCEPTED)
        conflict = next(obj for s, obj in results if s == HTTPStatus.CONFLICT)
        # Return shapes unchanged.
        self.assertEqual(accepted, {"ok": True, "pid": accepted["pid"], "engagement": EID})
        self.assertEqual(conflict, {"error": "run already in progress", "pid": conflict["pid"]})

        # The single tracked proc is the one that launched, and the loser reports ITS pid.
        self.assertIn(EID, cc._RUNS)
        tracked = cc._RUNS[EID]
        self.assertIsNone(tracked.poll())
        self.assertEqual(accepted["pid"], tracked.pid)
        self.assertEqual(conflict["pid"], tracked.pid,
                         "CONFLICT should report the winner's tracked pid, not a second spawn")
        # The fresh launch forgot how the last run ended.
        self.assertNotIn(EID, cc._ENDED)


if __name__ == "__main__":
    unittest.main()
