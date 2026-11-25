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
import json
import pathlib
import subprocess
import sys
import tempfile
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
