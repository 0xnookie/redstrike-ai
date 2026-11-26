#!/usr/bin/env python3
"""
Unit tests for scripts/rs_http.py -- the engagement-aware HTTP primitive.

Guarantees under test (the three the task pins, plus the scope.yaml loader + matcher):
  * the rate cap really throttles (a full 1s window forces a positive sleep);
  * an out-of-scope / unknown host is REFUSED (ScopeError, nothing hits the wire);
  * Authorization / Cookie / token secrets are REDACTED in runtime/http_log.jsonl.

No test makes a real network call: `request()` is driven with a STUB opener (and, where it
matters, an injected clock/sleeper), so the wire is never touched. Exercised against TEMP
engagement fixtures only. Stdlib only, runnable as `python test_rs_http.py` (the CI convention).
"""
import http.server
import json
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = pathlib.Path(__file__).resolve()
SCRIPTS = HERE.parents[1]
sys.path.insert(0, str(SCRIPTS))

import rs_http  # noqa: E402


SCOPE = {
    "in_scope": {"domains": ["*.example.com", "api.example.com"], "cidrs": ["203.0.113.0/24"],
                 "urls": ["https://portal.acme.io/login"]},
    "out_of_scope": {"domains": ["admin.example.com"], "cidrs": ["203.0.113.200/29"]},
    "rules": {"rate_limit_rps": 5},
}


class _FakeHeaders:
    def __init__(self, d):
        self._d = d

    def items(self):
        return self._d.items()


class _FakeResp:
    """Stands in for a urllib response object (status / headers / read)."""
    def __init__(self, status=200, headers=None, body=b"ok"):
        self.status = status
        self.headers = _FakeHeaders(headers or {"Content-Type": "text/plain"})
        self._body = body

    def getcode(self):
        return self.status

    def read(self):
        return self._body


class _FakeOpener:
    """Records the requests it is handed; never touches the network."""
    def __init__(self, resp=None):
        self.resp = resp or _FakeResp()
        self.calls = []

    def open(self, req, timeout=None):
        self.calls.append(req)
        return self.resp


def _eng():
    tmp = tempfile.TemporaryDirectory()
    return tmp, pathlib.Path(tmp.name)


class TestThrottle(unittest.TestCase):
    """The rate cap is a real client-side throttle (pure function, proven with no clock/network)."""

    def test_full_window_forces_positive_sleep(self):
        # 5 requests already inside the 1s window at rps=5 -> the 6th must WAIT for the oldest to age out.
        sleep, ts = rs_http._throttle_sleep([0.1, 0.3, 0.5, 0.7, 0.9], 5, 1.0)
        self.assertGreater(sleep, 0.0)
        self.assertTrue(ts)

    def test_empty_window_no_sleep(self):
        sleep, ts = rs_http._throttle_sleep([], 5, 1.0)
        self.assertEqual(sleep, 0.0)
        self.assertIn(1.0, ts)

    def test_request_throttles_via_injected_sleeper(self):
        """request() must actually CALL the throttle: a pre-seeded full window makes it sleep."""
        tmp, eng = _eng()
        self.addCleanup(tmp.cleanup)
        (eng / "runtime").mkdir()
        (eng / "runtime" / rs_http.RATE_STATE_NAME).write_text(
            json.dumps({"ts": [9.5, 9.6, 9.7, 9.8, 9.9]}), encoding="utf-8")
        slept = []
        rs_http.request("GET", "https://app.example.com/x", engagement=eng, scope=SCOPE,
                        opener=_FakeOpener(), clock=lambda: 10.0, sleeper=slept.append)
        self.assertTrue(slept and slept[0] > 0, "a full window at request time must sleep")

    def test_resolve_rps_default_and_clamp(self):
        self.assertEqual(rs_http.resolve_rps({"rules": {}}), rs_http.DEFAULT_RPS)
        self.assertEqual(rs_http.resolve_rps(SCOPE), 5.0)
        self.assertEqual(rs_http.resolve_rps(SCOPE, max_rps=2), 2.0)   # clamp below scope


class TestGlobalSlotReservation(unittest.TestCase):
    """The throttle is a GLOBAL slot reserver: chaining reservations the way K concurrent processes
    would (each reserving under the lock, then persisting its slot BEFORE sleeping) keeps the SUM of
    all processes' rate <= the cap — at most `rps` sends in any window (pure, no clock/network)."""

    def _chain(self, rps, arrivals, window=None):
        window = rs_http.RATE_WINDOW_SEC if window is None else window
        state, sends = [], []
        for now in arrivals:
            sl, state = rs_http._throttle_sleep(list(state), rps, now, window)
            sends.append(now + sl)           # the reserved send time this "process" will sleep until
        return sorted(sends)

    def test_concurrent_arrivals_never_exceed_cap(self):
        rps, window = 3, rs_http.RATE_WINDOW_SEC
        sends = self._chain(rps, [0.0] * 9)  # 9 processes all arriving at once, cap 3/s
        # any rps+1 consecutive reserved sends must span at least one window
        for i in range(len(sends) - rps):
            self.assertGreaterEqual(sends[i + rps] - sends[i], window - 1e-9)
        # an initial burst of exactly `rps` is allowed, then the rest is spaced out
        self.assertEqual(sends[:rps], [0.0] * rps)
        self.assertGreaterEqual(sends[-1], 2 * window - 1e-9)

    def test_future_reservations_constrain_later_processes(self):
        # a process arriving mid-window must schedule AFTER the slots already reserved by its peers,
        # not fire immediately off its own empty view — that is the per-process blind spot the fix closes.
        rps = 2
        sl, state = rs_http._throttle_sleep([], rps, 0.0)
        self.assertEqual(sl, 0.0)
        sl, state = rs_http._throttle_sleep(list(state), rps, 0.0)   # 2nd — still inside the burst
        self.assertEqual(sl, 0.0)
        sl, state = rs_http._throttle_sleep(list(state), rps, 0.0)   # 3rd — burst spent, must wait
        self.assertGreater(sl, 0.0)

    def test_unlimited_when_rps_zero(self):
        sl, state = rs_http._throttle_sleep([1.0, 2.0], 0, 3.0)
        self.assertEqual(sl, 0.0)

    def test_state_is_bounded(self):
        state = []
        for i in range(rs_http.RATE_MAX_KEEP * 2):
            _, state = rs_http._throttle_sleep(list(state), 1000, float(i) / 1000.0)
        self.assertLessEqual(len(state), rs_http.RATE_MAX_KEEP)


class TestRateLock(unittest.TestCase):
    """The cross-process file lock serialises the shared-window read-modify-write (POSIX + Windows)."""

    def test_acquire_release_and_mutual_exclusion(self):
        tmp, eng = _eng()
        self.addCleanup(tmp.cleanup)
        a = rs_http._RateLock(eng)
        self.assertTrue(a.acquire())
        self.assertTrue(a.path.is_file(), "the lock file is held")
        b = rs_http._RateLock(eng, timeout=0.2)
        self.assertFalse(b.acquire(), "a second holder cannot acquire while the first holds it")
        a.release()
        self.assertFalse(a.path.exists(), "release removes the lock file")
        self.assertTrue(b.acquire(), "the lock is acquirable once freed")
        b.release()

    def test_stale_lock_is_stolen(self):
        tmp, eng = _eng()
        self.addCleanup(tmp.cleanup)
        a = rs_http._RateLock(eng)
        self.assertTrue(a.acquire())      # leave it "held" but make it look stale
        import os
        old = time.time() - 60
        os.utime(a.path, (old, old))
        b = rs_http._RateLock(eng, timeout=0.5, stale=1.0)
        self.assertTrue(b.acquire(), "a lock older than `stale` must be stealable (crashed holder)")
        b.release()


class _RecordingHandler(http.server.BaseHTTPRequestHandler):
    arrivals: list = []
    _lock = threading.Lock()

    def do_GET(self):               # noqa: N802
        with _RecordingHandler._lock:
            _RecordingHandler.arrivals.append(time.monotonic())
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):      # silence the server log
        return


class TestConcurrentProcessesRespectGlobalCap(unittest.TestCase):
    """The fix, end-to-end: spawn K CONCURRENT rs_http CLI invocations sharing one engagement and
    assert the COMBINED request rate they land on a loopback server stays <= the scope cap. A broken
    per-process throttle lets all K fire at once (K x the cap) — the estate-wide WAF-ban risk."""

    def test_six_concurrent_invocations_stay_under_cap(self):
        rps, K, window = 2, 6, rs_http.RATE_WINDOW_SEC
        _RecordingHandler.arrivals = []
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _RecordingHandler)
        port = srv.server_address[1]
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            tmp, eng = _eng()
            self.addCleanup(tmp.cleanup)
            (eng / "runtime").mkdir()
            (eng / "runtime" / "scope.json").write_text(
                json.dumps({"in_scope": {}, "out_of_scope": {}, "rules": {"rate_limit_rps": rps}}),
                encoding="utf-8")
            url = f"http://127.0.0.1:{port}/"
            # launch all K at once (non-blocking) so they genuinely contend for the shared window
            procs = [subprocess.Popen(
                [sys.executable, str(SCRIPTS / "rs_http.py"), "--engagement", str(eng), "GET", url],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for _ in range(K)]
            for p in procs:
                self.assertEqual(p.wait(timeout=90), 0)
        finally:
            srv.shutdown()
            srv.server_close()
            th.join(timeout=5)

        arrivals = sorted(_RecordingHandler.arrivals)
        self.assertEqual(len(arrivals), K, "every invocation should have reached the server once")
        span = arrivals[-1] - arrivals[0]
        # K=6 single-request processes at 2 rps must spread across ~3 windows (~2s). An unlocked /
        # per-process throttle would fire all 6 together (span ~0). 1.0s is well clear of that floor.
        self.assertGreaterEqual(
            span, 1.0, f"concurrent invocations were not throttled globally (span={span:.3f}s)")
        # The reserver schedules up to `rps` sends per ALIGNED window (an initial burst of `rps`, then one
        # slot per window). The test counts a SLIDING window over real ARRIVALS: a reservation can only fire
        # at-or-after its slot (it sleeps until send_at), so under scheduling jitter on a loaded runner a late
        # slot bunches toward the NEXT group — never earlier — and a sliding window can straddle at most two
        # adjacent groups, i.e. 2*rps. More than that would mean the per-process throttle isn't sharing the
        # global budget — a case the span>=1.0s assertion above already fails hard (a broken throttle fires
        # all K at once: span~0 AND worst==K).
        worst = max(sum(1 for b in arrivals if a <= b < a + window) for a in arrivals)
        self.assertLessEqual(
            worst, 2 * rps, f"a {window}s window held {worst} requests (cap {rps}) — aggregate over 2x cap")


class TestScopeRefusal(unittest.TestCase):
    """An out-of-scope / unknown host is a hard stop — ScopeError, and the opener is never called."""

    def test_out_of_scope_domain_refused(self):
        tmp, eng = _eng()
        self.addCleanup(tmp.cleanup)
        op = _FakeOpener()
        with self.assertRaises(rs_http.ScopeError):
            rs_http.request("GET", "https://admin.example.com/secret", engagement=eng, scope=SCOPE, opener=op)
        self.assertEqual(op.calls, [], "refused request must not reach the opener")

    def test_unknown_host_refused(self):
        tmp, eng = _eng()
        self.addCleanup(tmp.cleanup)
        with self.assertRaises(rs_http.ScopeError):
            rs_http.request("GET", "https://evil.com/", engagement=eng, scope=SCOPE, opener=_FakeOpener())

    def test_out_of_scope_cidr_refused(self):
        tmp, eng = _eng()
        self.addCleanup(tmp.cleanup)
        with self.assertRaises(rs_http.ScopeError):
            rs_http.request("GET", "http://203.0.113.201/", engagement=eng, scope=SCOPE, opener=_FakeOpener())

    def test_in_scope_allowed(self):
        tmp, eng = _eng()
        self.addCleanup(tmp.cleanup)
        op = _FakeOpener(_FakeResp(status=200, body=b"hello"))
        r = rs_http.request("GET", "https://app.example.com/x", engagement=eng, scope=SCOPE, opener=op)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body, b"hello")
        self.assertEqual(len(op.calls), 1)

    def test_url_host_counts_as_in_scope(self):
        tmp, eng = _eng()
        self.addCleanup(tmp.cleanup)
        r = rs_http.request("GET", "https://portal.acme.io/login", engagement=eng, scope=SCOPE,
                            opener=_FakeOpener())
        self.assertEqual(r.status, 200)


class TestRedaction(unittest.TestCase):
    """Authorization / Cookie / token secrets are redacted in the JSONL log (never written raw)."""

    def test_secrets_redacted_in_log(self):
        tmp, eng = _eng()
        self.addCleanup(tmp.cleanup)
        rs_http.request(
            "GET", "https://app.example.com/me?token=SUPERSECRET&page=2", engagement=eng, scope=SCOPE,
            headers={"Authorization": "Bearer AAABBBCCC", "Cookie": "session=DEADBEEF", "Accept": "*/*"},
            opener=_FakeOpener())
        log = (eng / "runtime" / rs_http.LOG_NAME).read_text(encoding="utf-8")
        # the raw secrets must NOT appear anywhere in the log
        for secret in ("AAABBBCCC", "DEADBEEF", "SUPERSECRET"):
            self.assertNotIn(secret, log)
        self.assertIn(rs_http.REDACTED, log)
        rec = json.loads(log.splitlines()[-1])
        self.assertEqual(rec["request_headers"]["Authorization"], rs_http.REDACTED)
        self.assertEqual(rec["request_headers"]["Cookie"], rs_http.REDACTED)
        self.assertEqual(rec["request_headers"]["Accept"], "*/*")   # a non-secret header is preserved
        self.assertIn("token=" + rs_http.REDACTED, rec["url"])
        self.assertIn("page=2", rec["url"])                          # a non-secret param is preserved
        # the record carries the pinned shape
        for k in ("ts", "method", "url", "host", "status", "elapsed_ms", "resp_bytes", "rung"):
            self.assertIn(k, rec)

    def test_redact_helpers(self):
        self.assertEqual(rs_http.redact_headers({"authorization": "x"})["authorization"], rs_http.REDACTED)
        self.assertNotIn("SECR3T", rs_http.redact_url("https://app.example.com/c?api_key=SECR3T&q=1"))
        self.assertIn("q=1", rs_http.redact_url("https://app.example.com/c?api_key=SECR3T&q=1"))


class TestWriteGate(unittest.TestCase):
    """The mechanical write-gate (RoE §2 / write-vs-probe.md): a MUTATING method needs a covering
    approval grant in runtime/approvals.json, OR a declared probe that cannot persist state. Reads are
    never gated; with no engagement context the gate is not applied; RS_WRITE_GATE=0 disables it."""

    URL = "https://app.example.com/api/comments"

    def _ctx_eng(self, grants=None):
        """A tempdir engagement WITH a runtime/ dir (so write-gate context is 'present'), optionally
        seeding runtime/approvals.json with a grants ledger."""
        tmp, eng = _eng()
        self.addCleanup(tmp.cleanup)
        (eng / "runtime").mkdir()
        if grants is not None:
            (eng / "runtime" / rs_http.APPROVALS_NAME).write_text(
                json.dumps({"grants": grants}), encoding="utf-8")
        return eng

    def test_mutating_no_approval_refused(self):
        eng = self._ctx_eng(grants=[])          # context present, empty ledger
        op = _FakeOpener()
        with self.assertRaises(rs_http.WriteGateError):
            rs_http.request("POST", self.URL, engagement=eng, scope=SCOPE, opener=op)
        self.assertEqual(op.calls, [], "a refused mutating request must not reach the opener")

    def test_mutating_no_approvals_file_refused(self):
        # context present (runtime/ exists) but NO approvals.json at all → still refused (fail-closed
        # inside an engagement: a write with no recorded grant is refused).
        eng = self._ctx_eng(grants=None)
        with self.assertRaises(rs_http.WriteGateError):
            rs_http.request("DELETE", self.URL, engagement=eng, scope=SCOPE, opener=_FakeOpener())

    def test_covering_grant_allows(self):
        eng = self._ctx_eng(grants=[{
            "scope_granted": "POST a benign marker to app.example.com/api/comments",
            "granted_by": "Op <op@x>", "granted_at": "2026-01-01T00:00:00Z",
            "write_class": "production-write"}])
        op = _FakeOpener(_FakeResp(status=201, body=b"created"))
        r = rs_http.request("POST", self.URL, engagement=eng, scope=SCOPE, opener=op)
        self.assertEqual(r.status, 201)
        self.assertEqual(len(op.calls), 1)
        rec = json.loads((eng / "runtime" / rs_http.LOG_NAME).read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(rec["write_gate"], "approved")

    def test_grant_for_other_endpoint_does_not_cover(self):
        # incident #1: a grant must not be stretched to an endpoint it never names.
        eng = self._ctx_eng(grants=[{
            "scope_granted": "POST to app.example.com/api/profile",
            "granted_by": "Op", "granted_at": "2026-01-01T00:00:00Z",
            "write_class": "production-write"}])
        with self.assertRaises(rs_http.WriteGateError):
            rs_http.request("POST", self.URL, engagement=eng, scope=SCOPE, opener=_FakeOpener())

    def test_parent_grant_covers_subresource(self):
        # a grant for the collection endpoint covers a dynamic sub-resource; a sibling tree does not.
        eng = self._ctx_eng(grants=[{
            "scope_granted": "DELETE a test record under app.example.com/api/comments",
            "granted_by": "Op", "granted_at": "2026-01-01T00:00:00Z", "write_class": "production-write"}])
        r = rs_http.request("DELETE", "https://app.example.com/api/comments/42",
                            engagement=eng, scope=SCOPE, opener=_FakeOpener())
        self.assertEqual(r.status, 200)
        with self.assertRaises(rs_http.WriteGateError):
            rs_http.request("DELETE", "https://app.example.com/api/profiles/42",
                            engagement=eng, scope=SCOPE, opener=_FakeOpener())

    def test_reversible_grant_without_delete_path_refused(self):
        eng = self._ctx_eng(grants=[{
            "scope_granted": "POST to app.example.com/api/comments",
            "granted_by": "Op", "granted_at": "2026-01-01T00:00:00Z",
            "write_class": "reversible-self-write"}])     # no delete_path
        with self.assertRaises(rs_http.WriteGateError):
            rs_http.request("POST", self.URL, engagement=eng, scope=SCOPE, opener=_FakeOpener())

    def test_reversible_grant_with_delete_path_allows(self):
        eng = self._ctx_eng(grants=[{
            "scope_granted": "POST to app.example.com/api/comments",
            "granted_by": "Op", "granted_at": "2026-01-01T00:00:00Z",
            "write_class": "reversible-self-write",
            "delete_path": "DELETE /api/comments/{id}"}])
        r = rs_http.request("POST", self.URL, engagement=eng, scope=SCOPE, opener=_FakeOpener())
        self.assertEqual(r.status, 200)

    def test_probe_with_basis_allowed_and_logged(self):
        eng = self._ctx_eng(grants=[])
        op = _FakeOpener()
        r = rs_http.request("POST", self.URL, engagement=eng, scope=SCOPE, opener=op,
                            probe=True, probe_basis="validation-failing-body")
        self.assertEqual(r.status, 200)
        self.assertEqual(len(op.calls), 1, "a declared probe reaches the wire")
        rec = json.loads((eng / "runtime" / rs_http.LOG_NAME).read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(rec["write_gate"], "probe")
        self.assertTrue(rec["probe"])
        self.assertEqual(rec["probe_basis"], "validation-failing-body")

    def test_probe_without_valid_basis_refused(self):
        eng = self._ctx_eng(grants=[])
        with self.assertRaises(rs_http.WriteGateError):
            rs_http.request("POST", self.URL, engagement=eng, scope=SCOPE, opener=_FakeOpener(),
                            probe=True, probe_basis="not-a-real-basis")

    def test_get_never_gated_in_engagement_context(self):
        eng = self._ctx_eng(grants=[])          # context present, no grants — a GET still passes
        r = rs_http.request("GET", self.URL, engagement=eng, scope=SCOPE, opener=_FakeOpener())
        self.assertEqual(r.status, 200)

    def test_no_context_mutating_not_gated(self):
        # bare tempdir, NO runtime/ dir → no engagement/approvals context → mutating not gated
        # (never break the read-heavy existing call sites / unit tests that carry no grant ledger).
        tmp, eng = _eng()
        self.addCleanup(tmp.cleanup)
        r = rs_http.request("POST", self.URL, engagement=eng, scope=SCOPE, opener=_FakeOpener())
        self.assertEqual(r.status, 200)

    def test_env_switch_disables_gate(self):
        import os
        eng = self._ctx_eng(grants=[])
        os.environ[rs_http.WRITE_GATE_ENV] = "0"
        try:
            r = rs_http.request("POST", self.URL, engagement=eng, scope=SCOPE, opener=_FakeOpener())
            self.assertEqual(r.status, 200)
        finally:
            os.environ.pop(rs_http.WRITE_GATE_ENV, None)

    def _seed_scope(self, eng):
        (eng / "runtime" / "scope.json").write_text(json.dumps(SCOPE), encoding="utf-8")

    def test_cli_mutating_refused_exit_2(self):
        # end-to-end via the CLI: a POST with no covering grant exits 2 (refusal), opener untouched.
        eng = self._ctx_eng(grants=[])
        self._seed_scope(eng)
        r = subprocess.run(
            [sys.executable, str(SCRIPTS / "rs_http.py"), "--engagement", str(eng),
             "POST", self.URL, "--data", "x=1"],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("no covering approval", r.stderr)

    def test_cli_probe_requires_basis(self):
        eng = self._ctx_eng(grants=[])
        self._seed_scope(eng)
        r = subprocess.run(
            [sys.executable, str(SCRIPTS / "rs_http.py"), "--engagement", str(eng),
             "POST", self.URL, "--probe"],
            capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--probe-basis", r.stderr)


class TestScopeLoading(unittest.TestCase):
    """load_scope reads the engagement's scope.yaml (stdlib mini-reader) and runtime/scope.json."""

    def test_loads_scope_yaml(self):
        tmp, eng = _eng()
        self.addCleanup(tmp.cleanup)
        (eng / "scope.yaml").write_text(
            "engagement: acme\n"
            "in_scope:\n"
            "  domains:\n"
            "    - \"*.example.com\"\n"
            "    - api.example.com\n"
            "  cidrs: []\n"
            "  urls: []\n"
            "out_of_scope:\n"
            "  domains:\n"
            "    - admin.example.com\n"
            "rules:\n"
            "  rate_limit_rps: 7\n", encoding="utf-8")
        scope = rs_http.load_scope(eng)
        self.assertIn("*.example.com", scope["in_scope"]["domains"])
        self.assertEqual(rs_http.resolve_rps(scope), 7.0)
        self.assertEqual(rs_http.classify("admin.example.com", scope), "out")
        self.assertEqual(rs_http.classify("app.example.com", scope), "in")

    def test_falls_back_to_scope_json(self):
        tmp, eng = _eng()
        self.addCleanup(tmp.cleanup)
        (eng / "runtime").mkdir()
        (eng / "runtime" / "scope.json").write_text(json.dumps(SCOPE), encoding="utf-8")
        scope = rs_http.load_scope(eng)
        self.assertEqual(rs_http.resolve_rps(scope), 5.0)

    def test_missing_scope_raises(self):
        tmp, eng = _eng()
        self.addCleanup(tmp.cleanup)
        with self.assertRaises(rs_http.ScopeError):
            rs_http.load_scope(eng)


class TestCli(unittest.TestCase):
    def test_selftest_exits_zero(self):
        r = subprocess.run([sys.executable, str(SCRIPTS / "rs_http.py"), "--selftest"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("OK", r.stdout)

    def test_help_runs(self):
        r = subprocess.run([sys.executable, str(SCRIPTS / "rs_http.py"), "--help"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("--engagement", r.stdout)


if __name__ == "__main__":
    unittest.main()
