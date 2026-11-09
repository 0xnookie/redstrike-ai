import json
import multiprocessing
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # cli/

from redstrike_cli.hooks import rate_gate as rg  # noqa: E402


def fixed_rng(v=0.5):
    return lambda: v


class TestCheckRateBudget(unittest.TestCase):
    def test_under_budget_passes_and_records(self):
        hs = rg._blank_host()
        d = rg.check(hs, now=1000.0, rps=5)
        self.assertEqual(d["decision"], "pass")
        self.assertEqual(len(hs["ts"]), 1)
        self.assertEqual(hs["total_requests"], 1)

    def test_over_budget_denies_within_window(self):
        hs = rg._blank_host()
        # fire rps requests at the same instant → the next is over budget
        for _ in range(5):
            self.assertEqual(rg.check(hs, now=1000.0, rps=5)["decision"], "pass")
        d = rg.check(hs, now=1000.0, rps=5)
        self.assertEqual(d["decision"], "deny")
        self.assertIn("rate budget", d["reason"])
        # a denied attempt is NOT recorded (so the window can drain)
        self.assertEqual(len(hs["ts"]), 5)

    def test_window_slides_and_frees_a_slot(self):
        hs = rg._blank_host()
        for _ in range(5):
            rg.check(hs, now=1000.0, rps=5)
        self.assertEqual(rg.check(hs, now=1000.0, rps=5)["decision"], "deny")
        # after the window fully slides, budget is available again
        self.assertEqual(rg.check(hs, now=1001.01, rps=5)["decision"], "pass")

    def test_rps_zero_means_unmetered(self):
        hs = rg._blank_host()
        for _ in range(50):
            self.assertEqual(rg.check(hs, now=1000.0, rps=0)["decision"], "pass")


class TestBreaker(unittest.TestCase):
    def test_block_opens_breaker(self):
        hs = rg._blank_host()
        rg.observe(hs, 429, now=1000.0, base_backoff=2.0, rng=fixed_rng())
        self.assertEqual(hs["blocks"], 1)
        self.assertGreater(hs["open_until"], 1000.0)
        # while open, check denies regardless of rate budget
        d = rg.check(hs, now=1000.5, rps=1000)
        self.assertEqual(d["decision"], "deny")
        self.assertIn("backing off", d["reason"])

    def test_backoff_is_exponential(self):
        hs = rg._blank_host()
        rg.observe(hs, 429, now=0.0, base_backoff=2.0, rng=fixed_rng())  # jitter *1.0
        first = hs["open_until"]
        rg.observe(hs, 429, now=0.0, base_backoff=2.0, rng=fixed_rng())
        second = hs["open_until"]
        self.assertAlmostEqual(first, 2.0, places=6)    # 2 * 2^0
        self.assertAlmostEqual(second, 4.0, places=6)   # 2 * 2^1

    def test_backoff_capped(self):
        hs = rg._blank_host()
        for _ in range(20):
            rg.observe(hs, 429, now=0.0, base_backoff=2.0, max_open=120.0, rng=fixed_rng())
        self.assertLessEqual(hs["open_until"], 120.0)

    def test_jitter_within_band(self):
        lo = rg._blank_host()
        hi = rg._blank_host()
        rg.observe(lo, 429, now=0.0, base_backoff=10.0, rng=fixed_rng(0.0))  # *0.8
        rg.observe(hi, 429, now=0.0, base_backoff=10.0, rng=fixed_rng(1.0))  # *1.2
        self.assertAlmostEqual(lo["open_until"], 8.0, places=6)
        self.assertAlmostEqual(hi["open_until"], 12.0, places=6)

    def test_success_closes_breaker(self):
        hs = rg._blank_host()
        rg.observe(hs, 429, now=0.0, rng=fixed_rng())
        rg.observe(hs, 200, now=0.0)
        self.assertEqual(hs["blocks"], 0)
        self.assertEqual(hs["open_until"], 0.0)

    def test_challenge_body_trips_even_on_200(self):
        hs = rg._blank_host()
        rg.observe(hs, 200, now=0.0, is_challenge=True, rng=fixed_rng())
        self.assertEqual(hs["blocks"], 1)
        self.assertGreater(hs["open_until"], 0.0)

    def test_unreadable_status_is_noop(self):
        hs = rg._blank_host()
        rg.observe(hs, None, now=0.0)
        self.assertEqual(hs["blocks"], 0)
        self.assertEqual(hs["open_until"], 0.0)

    def test_half_open_probe_after_cooldown(self):
        hs = rg._blank_host()
        rg.observe(hs, 429, now=0.0, base_backoff=2.0, rng=fixed_rng())
        # once open_until has passed, a single probe is allowed through
        self.assertEqual(rg.check(hs, now=10.0, rps=1000)["decision"], "pass")


class TestParseStatus(unittest.TestCase):
    def test_http_status_line(self):
        self.assertEqual(rg.parse_status("HTTP/1.1 429 Too Many Requests"), (429, True))

    def test_http2_status_line(self):
        s, c = rg.parse_status("HTTP/2 403 \nserver: cloudflare")
        self.assertEqual(s, 403)

    def test_last_status_line_wins(self):
        txt = "HTTP/1.1 301 Moved\nLocation: /x\n\nHTTP/1.1 200 OK"
        self.assertEqual(rg.parse_status(txt)[0], 200)

    def test_bare_http_code(self):
        self.assertEqual(rg.parse_status("some body\n429\n")[0], 429)

    def test_challenge_signature(self):
        s, c = rg.parse_status("<title>Just a moment...</title> cf-mitigated: challenge")
        self.assertTrue(c)

    def test_nothing_parseable(self):
        self.assertEqual(rg.parse_status("just a normal page with no code"), (None, False))

    def test_empty(self):
        self.assertEqual(rg.parse_status(""), (None, False))


class TestTargetHosts(unittest.TestCase):
    def test_webfetch_host(self):
        self.assertEqual(rg.target_hosts("WebFetch", {"url": "https://api.acme.com/x"}), ["api.acme.com"])

    def test_bash_hosts(self):
        hosts = rg.target_hosts("Bash", {"command": "curl https://a.acme.com; curl https://b.acme.com"})
        self.assertIn("a.acme.com", hosts)
        self.assertIn("b.acme.com", hosts)

    def test_localhost_filtered(self):
        self.assertEqual(rg.target_hosts("WebFetch", {"url": "http://localhost:8080/x"}), [])

    def test_non_network_tool(self):
        self.assertEqual(rg.target_hosts("Read", {"file_path": "/etc/hosts"}), [])


class TestDecideMultiHost(unittest.TestCase):
    def test_per_host_isolation(self):
        state = {}
        # burn host A's budget; host B must stay unaffected
        for _ in range(5):
            rg.decide(state, ["a.acme.com"], now=1000.0, rps=5)
        da = rg.decide(state, ["a.acme.com"], now=1000.0, rps=5)
        db = rg.decide(state, ["b.acme.com"], now=1000.0, rps=5)
        self.assertEqual(da["decision"], "deny")
        self.assertEqual(da["host"], "a.acme.com")
        self.assertEqual(db["decision"], "pass")

    def test_ignorable_hosts_skipped(self):
        state = {}
        d = rg.decide(state, ["localhost", "127.0.0.1"], now=1000.0, rps=1)
        self.assertEqual(d["decision"], "pass")
        self.assertEqual(state.get("hosts", {}), {})


class TestResolveRps(unittest.TestCase):
    def _scope(self, rules):
        p = pathlib.Path(tempfile.mkdtemp()) / "scope.json"
        p.write_text(json.dumps({"rules": rules}))
        return str(p)

    def test_reads_scope_value(self):
        self.assertEqual(rg.resolve_rps(self._scope({"rate_limit_rps": 20}), None), 20.0)

    def test_missing_falls_back_to_default(self):
        self.assertEqual(rg.resolve_rps(self._scope({}), None), rg.DEFAULT_RPS)

    def test_max_rps_clamps_below_scope(self):
        self.assertEqual(rg.resolve_rps(self._scope({"rate_limit_rps": 20}), 3), 3.0)

    def test_max_rps_does_not_raise_above_scope(self):
        self.assertEqual(rg.resolve_rps(self._scope({"rate_limit_rps": 2}), 10), 2.0)

    def test_unreadable_scope_falls_back(self):
        self.assertEqual(rg.resolve_rps("/no/such/scope.json", None), rg.DEFAULT_RPS)


class TestPersistence(unittest.TestCase):
    def test_round_trip_and_lock(self):
        d = pathlib.Path(tempfile.mkdtemp())
        state_path = d / "runtime" / "rate_state.json"

        def _txn(state):
            hs = rg._host_state(state, "api.acme.com")
            hs["blocks"] = 3
            return "ok", state

        self.assertEqual(rg.with_state(state_path, _txn), "ok")
        self.assertTrue(state_path.is_file())
        reloaded = json.loads(state_path.read_text())
        self.assertEqual(reloaded["hosts"]["api.acme.com"]["blocks"], 3)

    def test_concurrent_increments_are_not_lost(self):
        d = pathlib.Path(tempfile.mkdtemp())
        state_path = d / "rate_state.json"
        state_path.write_text("{}")
        procs = [multiprocessing.Process(target=_bump, args=(str(state_path),)) for _ in range(12)]
        for p in procs:
            p.start()
        for p in procs:
            p.join()
        total = json.loads(state_path.read_text())["hosts"]["api.acme.com"]["total_requests"]
        self.assertEqual(total, 12)  # no lost updates under the lock


def _bump(path):  # module-level so it is picklable for multiprocessing
    from redstrike_cli.hooks import rate_gate as rg2

    def _txn(state):
        hs = rg2._host_state(state, "api.acme.com")
        hs["total_requests"] = int(hs.get("total_requests", 0)) + 1
        return None, state

    rg2.with_state(pathlib.Path(path), _txn)


class TestHookIO(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        self.scope = self.d / "scope.json"
        self.scope.write_text(json.dumps({"rules": {"rate_limit_rps": 2}}))
        self.state = self.d / "rate_state.json"

    def test_pre_denies_when_over_budget(self):
        payload = {"tool_name": "WebFetch", "tool_input": {"url": "https://api.acme.com/x"}}
        for _ in range(2):
            rg.run_pre(payload, str(self.scope), self.state, None, now=1000.0)
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rg.run_pre(payload, str(self.scope), self.state, None, now=1000.0)
        out = json.loads(buf.getvalue())
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("rate-gate", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_pre_passes_silently_under_budget(self):
        payload = {"tool_name": "WebFetch", "tool_input": {"url": "https://api.acme.com/x"}}
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rg.run_pre(payload, str(self.scope), self.state, None, now=1000.0)
        self.assertEqual(buf.getvalue().strip(), "")

    def test_observe_then_pre_denies_via_breaker(self):
        tgt = {"tool_name": "Bash", "tool_input": {"command": "curl https://api.acme.com/x"}}
        obs = dict(tgt, tool_response="HTTP/1.1 429 Too Many Requests")
        rg.run_observe(obs, self.state, now=1000.0)
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rg.run_pre(tgt, str(self.scope), self.state, None, now=1000.5)
        out = json.loads(buf.getvalue())
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("backing off", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_pre_no_host_is_noop(self):
        payload = {"tool_name": "Read", "tool_input": {"file_path": "x.txt"}}
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = rg.run_pre(payload, str(self.scope), self.state, None, now=1000.0)
        self.assertEqual(rc, 0)
        self.assertEqual(buf.getvalue().strip(), "")

    def test_main_fails_open_on_bad_payload(self):
        # no state path derivable + junk stdin → must not raise, must not deny
        rc = rg.main(["--scope", str(self.scope), "--state", str(self.state)])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
