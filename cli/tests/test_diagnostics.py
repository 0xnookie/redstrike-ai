import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # cli/

from redstrike_cli import diagnostics as dg  # noqa: E402


def _transport(status="healthy", block_rate=0.0, worst=None, hosts=None):
    return {"hosts": hosts or [], "overall": {"block_rate": block_rate, "worst_host": worst, "status": status}}


class TestClassifyOutcome(unittest.TestCase):
    def test_produced_findings_wins(self):
        out, reason = dg.classify_outcome(
            {"findings_count": 2, "engine_rc": 1}, None, None, _transport())
        self.assertEqual(out, dg.PRODUCED)
        self.assertIsNone(reason)

    def test_failed_on_nonzero_rc(self):
        out, reason = dg.classify_outcome(
            {"findings_count": 0, "engine_rc": 127}, {"categories": [{"status": "attempted"}]},
            {"surfaces": [{"status": "tested"}]}, _transport())
        self.assertEqual(out, dg.FAILED)
        self.assertIn("127", reason)

    def test_clean_tested_when_surface_tested_and_healthy(self):
        out, reason = dg.classify_outcome(
            {"findings_count": 0, "engine_rc": 0},
            {"categories": [{"status": "attempted"}]},
            {"surfaces": [{"status": "tested"}]},
            _transport())
        self.assertEqual(out, dg.CLEAN)
        self.assertIsNone(reason)

    def test_degraded_when_blocked(self):
        th = _transport(status="blocked", block_rate=0.94, worst="api.acme.com",
                        hosts=[{"host": "api.acme.com", "waf": "cloudflare"}])
        out, reason = dg.classify_outcome(
            {"findings_count": 0, "engine_rc": 0},
            {"categories": [{"status": "attempted"}]},
            {"surfaces": [{"status": "tested"}]}, th)
        self.assertEqual(out, dg.DEGRADED)
        self.assertIn("94%", reason)
        self.assertIn("api.acme.com", reason)
        self.assertIn("cloudflare", reason)
        self.assertIn("UNRELIABLE", reason)

    def test_degraded_when_no_surface(self):
        out, reason = dg.classify_outcome(
            {"findings_count": 0, "engine_rc": 0}, None, {"surfaces": []}, _transport())
        self.assertEqual(out, dg.DEGRADED)
        self.assertIn("no attack surface", reason)

    def test_degraded_when_all_skipped(self):
        cov = {"categories": [{"status": "skipped"}, {"status": "skipped"}, {"status": "n/a"}]}
        out, reason = dg.classify_outcome(
            {"findings_count": 0, "engine_rc": 0}, cov, {"surfaces": [{"status": "discovered"}]}, _transport())
        self.assertEqual(out, dg.DEGRADED)
        self.assertIn("no vulnerability class was attempted", reason)

    def test_degraded_on_tool_failures(self):
        out, reason = dg.classify_outcome(
            {"findings_count": 0, "engine_rc": 0,
             "tool_failures": [{"tool": "ffuf", "count": 3}]},
            {"categories": [{"status": "attempted"}]},
            {"surfaces": [{"status": "tested"}]}, _transport())
        self.assertEqual(out, dg.DEGRADED)
        self.assertIn("ffuf", reason)
        self.assertIn("3 tool", reason)

    def test_degraded_on_cap_hit(self):
        out, reason = dg.classify_outcome(
            {"findings_count": 0, "engine_rc": 0, "cap_hit": True},
            {"categories": [{"status": "attempted"}]},
            {"surfaces": [{"status": "tested"}]}, _transport())
        self.assertEqual(out, dg.DEGRADED)
        self.assertIn("cap", reason)

    def test_degraded_when_no_evidence_of_testing(self):
        # zero findings, nothing attempted, no ledgers at all → cannot claim clean
        out, reason = dg.classify_outcome(
            {"findings_count": 0, "engine_rc": 0}, None, None, _transport())
        self.assertEqual(out, dg.DEGRADED)
        self.assertIn("no evidence", reason)

    def test_blocked_takes_priority_over_surface(self):
        # blocked is the root cause and must be reported even if surface is also zero
        th = _transport(status="blocked", block_rate=0.8, worst="x.com",
                        hosts=[{"host": "x.com", "waf": None}])
        out, reason = dg.classify_outcome(
            {"findings_count": 0, "engine_rc": 0}, None, {"surfaces": []}, th)
        self.assertEqual(out, dg.DEGRADED)
        self.assertIn("blocked/challenged", reason)


class TestTransportRollup(unittest.TestCase):
    def test_healthy_host(self):
        rs = {"hosts": {"a.com": {"total_requests": 10, "total_blocks": 0,
                                  "statuses": {"200": 10}, "challenges": 0}}}
        th = dg.transport_rollup(rs)
        h = th["hosts"][0]
        self.assertEqual(h["classification"], "healthy")
        self.assertEqual(h["block_rate"], 0.0)
        self.assertEqual(h["statuses"], {"200": 10})
        self.assertEqual(th["overall"]["status"], "healthy")
        self.assertIsNone(th["overall"]["worst_host"])

    def test_blocked_host_and_overall(self):
        rs = {"hosts": {
            "a.com": {"total_requests": 10, "total_blocks": 9, "waf": "cloudflare",
                      "statuses": {"403": 9, "200": 1}, "challenges": 2},
            "b.com": {"total_requests": 10, "total_blocks": 0, "statuses": {"200": 10}},
        }}
        th = dg.transport_rollup(rs)
        by_host = {h["host"]: h for h in th["hosts"]}
        self.assertEqual(by_host["a.com"]["classification"], "blocked")
        self.assertAlmostEqual(by_host["a.com"]["block_rate"], 0.9)
        self.assertEqual(by_host["a.com"]["waf"], "cloudflare")
        self.assertEqual(by_host["b.com"]["classification"], "healthy")
        self.assertEqual(th["overall"]["status"], "blocked")
        self.assertEqual(th["overall"]["worst_host"], "a.com")

    def test_degraded_host(self):
        rs = {"hosts": {"a.com": {"total_requests": 10, "total_blocks": 2, "statuses": {"429": 2, "200": 8}}}}
        th = dg.transport_rollup(rs)
        self.assertEqual(th["hosts"][0]["classification"], "degraded")
        self.assertEqual(th["overall"]["status"], "degraded")

    def test_empty_state(self):
        th = dg.transport_rollup({})
        self.assertEqual(th["hosts"], [])
        self.assertEqual(th["overall"], {"block_rate": 0.0, "worst_host": None, "status": "healthy"})


class TestExtractors(unittest.TestCase):
    def test_empty_recon_flag(self):
        er = dg.empty_recon({"surfaces": []}, {"signals": []}, {"live_hosts": []})
        self.assertTrue(er["flag"])
        self.assertEqual(er, {"flag": True, "surface_discovered": 0, "signals": 0, "hosts_live": 0})

    def test_empty_recon_populated(self):
        er = dg.empty_recon(
            {"surfaces": [{"id": "1"}, {"id": "2"}]},
            {"signals": ["param:injectable", "sink:dom"]},
            {"live_hosts": [{"host": "a", "live": True}, {"host": "b"}, {"host": "c", "live": False}]})
        self.assertEqual(er, {"flag": False, "surface_discovered": 2, "signals": 2, "hosts_live": 2})

    def test_phase_tally(self):
        cov = {"categories": [
            {"id": "xss", "status": "attempted", "findings_count": 1},
            {"id": "sqli", "status": "skipped"},
        ]}
        self.assertEqual(dg.phase_tally(cov), [
            {"class": "xss", "attempted": True, "produced": 1},
            {"class": "sqli", "attempted": False, "produced": 0},
        ])

    def test_gate_summary_shape(self):
        gs = dg.gate_summary({"categories": [{"status": "attempted"}]},
                             {"surfaces": [{"status": "tested"}]}, 3, None)
        self.assertEqual(set(gs), {"coverage", "surface", "recall", "findings"})
        self.assertEqual(gs["findings"], 3)
        self.assertEqual(gs["recall"], "n/a")

    def test_accepted_findings_count(self):
        findings = [{"status": "accepted"}, {"status": "verified"}, {"status": "rejected"}, {"status": "candidate"}]
        self.assertEqual(dg.accepted_findings_count(findings), 2)
        self.assertEqual(dg.accepted_findings_count(None), 0)


class _FakeSummary:
    def __init__(self, **kw):
        self.subtype = kw.get("subtype", "success")
        self.stop_reason = kw.get("stop_reason", "")
        self.tool_failures = kw.get("tool_failures", [])
        self.non_json_lines = kw.get("non_json_lines", 0)
        self.non_json_sample = kw.get("non_json_sample", "")


class TestSummaryFromRun(unittest.TestCase):
    def test_none_summary_interactive(self):
        sm = dg.summary_from_run(None, findings_count=0, engine_rc=0)
        self.assertEqual(sm["findings_count"], 0)
        self.assertEqual(sm["tool_failures"], [])
        self.assertEqual(sm["exceptions"], [])
        self.assertFalse(sm["cap_hit"])

    def test_non_success_subtype_is_exception_and_cap(self):
        sm = dg.summary_from_run(_FakeSummary(subtype="error_max_turns"), 0, 0)
        self.assertTrue(sm["cap_hit"])
        self.assertTrue(any("error_max_turns" in e["message"] for e in sm["exceptions"]))

    def test_non_json_lines_become_exception(self):
        sm = dg.summary_from_run(_FakeSummary(non_json_lines=4, non_json_sample="oops warning"), 0, 0)
        self.assertTrue(any("non-JSON" in e["message"] and "oops warning" in e["message"]
                            for e in sm["exceptions"]))


class TestWriteAndAssemble(unittest.TestCase):
    def _rec(self, **kw):
        d = dg.Diagnostics(session="sess-123456789", mode="autonomous",
                           outcome=dg.DEGRADED, degraded_reason=kw.get("reason", "blocked"),
                           engine_rc=0, gate_rc=1)
        return d.to_record()

    def test_to_record_has_exact_pinned_keys_in_order(self):
        rec = dg.Diagnostics().to_record()
        self.assertEqual(list(rec.keys()), [
            "session", "mode", "started", "ended", "engine_rc", "gate_rc", "outcome",
            "degraded_reason", "findings_count", "tool_failures", "exceptions",
            "transport_health", "empty_recon", "phase_tally", "gate_summary"])

    def test_write_appends_and_top_level_shape(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d) / "acme-eng"
            (eng / "runtime").mkdir(parents=True)
            dg.write(eng, self._rec())
            dg.write(eng, self._rec())
            doc = json.loads((eng / "runtime" / "diagnostics.json").read_text(encoding="utf-8"))
            self.assertEqual(set(doc.keys()), {"engagement", "generated_at", "runs"})
            self.assertEqual(doc["engagement"], "acme-eng")
            self.assertEqual(len(doc["runs"]), 2)

    def test_error_log_written_and_redacted(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d) / "eng"
            (eng / "runtime").mkdir(parents=True)
            rec = dg.Diagnostics(
                session="s", mode="autonomous", outcome=dg.DEGRADED,
                degraded_reason="x", engine_rc=0, gate_rc=0,
                exceptions=[{"where": "x", "message": "leak password=supersecret123 here"}],
            ).to_record()
            dg.write(eng, rec)
            log = (eng / "runtime" / "error.log").read_text(encoding="utf-8")
            self.assertIn("outcome=degraded-empty", log)
            self.assertIn("[REDACTED:", log)
            self.assertNotIn("supersecret123", log)

    def test_assemble_reads_files_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d) / "eng"
            (eng / "runtime").mkdir(parents=True)
            (eng / "runtime" / "rate_state.json").write_text(json.dumps({"hosts": {
                "api.acme.com": {"total_requests": 10, "total_blocks": 9, "waf": "cloudflare",
                                 "statuses": {"403": 9, "200": 1}, "challenges": 1}}}))
            (eng / "coverage_ledger.json").write_text(json.dumps({"categories": [
                {"id": "xss", "status": "attempted", "findings_count": 0}]}))
            (eng / "surface_ledger.json").write_text(json.dumps({"surfaces": [
                {"id": "e1", "kind": "endpoint", "value": "/a", "status": "tested"}]}))
            (eng / "findings.json").write_text(json.dumps([]))
            (eng / "signals.json").write_text(json.dumps({"signals": ["param:injectable"]}))
            (eng / "host_discovery.json").write_text(json.dumps({"live_hosts": [{"host": "api.acme.com"}]}))

            rec = dg.assemble(eng, session="abc", mode="autonomous",
                              started="t0", ended="t1", engine_rc=0, gate_rc=0, summary=None).to_record()
            self.assertEqual(rec["outcome"], dg.DEGRADED)       # blocked transport
            self.assertIn("blocked/challenged", rec["degraded_reason"])
            self.assertEqual(rec["transport_health"]["overall"]["status"], "blocked")
            self.assertEqual(rec["transport_health"]["overall"]["worst_host"], "api.acme.com")
            self.assertEqual(rec["empty_recon"]["signals"], 1)
            self.assertEqual(rec["phase_tally"], [{"class": "xss", "attempted": True, "produced": 0}])
            self.assertEqual(rec["gate_summary"]["findings"], 0)

    def test_assemble_missing_files_is_degraded_not_crash(self):
        with tempfile.TemporaryDirectory() as d:
            eng = pathlib.Path(d) / "eng"
            (eng / "runtime").mkdir(parents=True)
            rec = dg.assemble(eng, session="x", mode="interactive",
                              started="", ended="", engine_rc=0, gate_rc=0, summary=None).to_record()
            self.assertEqual(rec["outcome"], dg.DEGRADED)
            self.assertTrue(rec["empty_recon"]["flag"])


if __name__ == "__main__":
    unittest.main()
