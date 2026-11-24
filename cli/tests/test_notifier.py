"""Tests for Feature 1 — run notifications with HARD evidence redaction (cli/redstrike_cli/notifier.py).

Covers:
  • the redaction GUARANTEE: no secret-shaped material can leave in the final outbound payload,
    even when smuggled via a template, a finding title or a collected log line; numbers survive.
  • config is default-OFF (no webhook → no-op), loads from engagement notify.json or env, and
    rejects a non-http(s) URL.
  • build_summary reads the diagnostics OUTCOME record + accepted Critical/High findings (title +
    class only, no evidence), honoring min_severity.
  • ${var} substitution (lone placeholder → typed value; embedded → interpolated).
  • notify_run end-to-end with an injected POST seam: payload is redacted BEFORE the POST, the
    notify_on outcome filter is honored, and a POST failure never raises.
  • the Collector tees runloop's emit callback.
"""
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # cli/

from redstrike_cli import notifier  # noqa: E402


def _eng_with_findings(tmp, findings):
    eng = pathlib.Path(tmp) / "eng"
    (eng / "runtime").mkdir(parents=True)
    (eng / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
    return eng


SECRETS = [
    "hunter2SuperSecret",
    "abc123SECRETtokenVALUE0000",
    "deadbeefdeadbeefdeadbeefdeadbeef",
    "AKIAIOSFODNN7EXAMPLE",
    "sk-liveABCDEFGHIJKLMNOPQRSTUV",
]


class TestRedactionGuarantee(unittest.TestCase):
    def test_redact_payload_strips_all_secret_shapes(self):
        payload = {
            "text": "Authorization: Bearer abc123SECRETtokenVALUE0000 and password=hunter2SuperSecret",
            "cookie": "Cookie: session=deadbeefdeadbeefdeadbeefdeadbeef",
            "akid": "AKIAIOSFODNN7EXAMPLE",
            "nested": {"api_key": "api_key: sk-liveABCDEFGHIJKLMNOPQRSTUV"},
            "list": ["token=hunter2SuperSecret"],
            "count": 7,
        }
        red = notifier.redact_payload(payload)
        flat = json.dumps(red)
        for bad in SECRETS:
            self.assertNotIn(bad, flat, f"secret leaked: {bad}")
        self.assertEqual(red["count"], 7)  # non-strings pass through

    def test_sanitize_strips_ansi_and_is_idempotent(self):
        s = "\x1b[33mtoken=hunter2SuperSecret\x1b[0m"
        once = notifier.sanitize_text(s)
        self.assertNotIn("hunter2SuperSecret", once)
        self.assertNotIn("\x1b[", once)
        self.assertEqual(once, notifier.sanitize_text(once))


class TestConfig(unittest.TestCase):
    def test_off_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = pathlib.Path(tmp) / "eng"
            eng.mkdir()
            self.assertIsNone(notifier.load_config(eng, env={}))

    def test_env_webhook_enables(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = pathlib.Path(tmp) / "eng"
            eng.mkdir()
            cfg = notifier.load_config(eng, env={"REDSTRIKE_NOTIFY_WEBHOOK": "https://h.example/x/TOKEN"})
            self.assertIsNotNone(cfg)
            self.assertEqual(cfg["webhook_url"], "https://h.example/x/TOKEN")
            self.assertEqual(cfg["min_severity"], "high")  # default

    def test_non_http_url_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = pathlib.Path(tmp) / "eng"
            eng.mkdir()
            self.assertIsNone(notifier.load_config(eng, env={"REDSTRIKE_NOTIFY_WEBHOOK": "file:///etc/passwd"}))

    def test_engagement_file_wins_over_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = pathlib.Path(tmp) / "eng"
            eng.mkdir()
            (eng / "notify.json").write_text(json.dumps({
                "webhook_url": "https://file.example/hook",
                "notify_on": ["failed"],
                "min_severity": "critical",
            }), encoding="utf-8")
            cfg = notifier.load_config(eng, env={"REDSTRIKE_NOTIFY_WEBHOOK": "https://env.example/hook"})
            self.assertEqual(cfg["webhook_url"], "https://file.example/hook")
            self.assertEqual(cfg["notify_on"], ["failed"])
            self.assertEqual(cfg["min_severity"], "critical")


class TestSummaryAndRender(unittest.TestCase):
    def test_critical_high_lines_redacted_and_filtered(self):
        findings = [
            {"status": "accepted", "severity": "critical", "class": "sqli",
             "title": "dump via password=hunter2SuperSecret"},
            {"status": "verified", "severity": "high", "type": "idor", "title": "cross-tenant read"},
            {"status": "accepted", "severity": "medium", "class": "csrf", "title": "ignored (below floor)"},
            {"status": "rejected", "severity": "critical", "class": "xss", "title": "not accepted"},
        ]
        lines = notifier.critical_high_lines(findings)
        self.assertEqual(len(lines), 2)  # only accepted Critical + High
        joined = " ".join(lines)
        self.assertIn("sqli", joined)
        self.assertIn("idor", joined)
        self.assertNotIn("hunter2SuperSecret", joined)  # title evidence redacted
        self.assertNotIn("medium", joined.lower())

    def test_build_summary_from_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = _eng_with_findings(tmp, [
                {"status": "accepted", "severity": "high", "class": "idor", "title": "t"},
            ])
            rec = {"outcome": "produced-findings", "degraded_reason": None,
                   "findings_count": 1, "ended": "2026-01-01T00:00:00Z"}
            s = notifier.build_summary(eng, rec)
            self.assertEqual(s["findings_count"], 1)
            self.assertEqual(s["critical_high_count"], 1)
            self.assertEqual(s["outcome"], "produced-findings")

    def test_render_typed_and_interpolated(self):
        summary = {"findings_count": 3, "engagement": "acme", "critical_high": ["a", "b"]}
        out = notifier.render_payload({
            "count": "${findings_count}",          # lone -> typed int
            "msg": "eng ${engagement} had ${findings_count}",  # embedded -> string
            "list": "${critical_high}",            # lone -> typed list
        }, summary)
        self.assertEqual(out["count"], 3)
        self.assertEqual(out["msg"], "eng acme had 3")
        self.assertEqual(out["list"], ["a", "b"])


class TestNotifyRun(unittest.TestCase):
    def test_noop_when_off(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = pathlib.Path(tmp) / "eng"
            eng.mkdir()
            res = notifier.notify_run(eng, {"outcome": "clean-tested"}, env={})
            self.assertTrue(res.skipped)
            self.assertFalse(res.sent)

    def test_sends_redacted_payload(self):
        captured = {}

        def fake_post(url, payload):
            captured["url"] = url
            captured["payload"] = payload
            return True, "HTTP 200"

        with tempfile.TemporaryDirectory() as tmp:
            eng = _eng_with_findings(tmp, [
                {"status": "accepted", "severity": "critical", "class": "sqli",
                 "title": "leak password=hunter2SuperSecret here"},
            ])
            rec = {"outcome": "produced-findings", "degraded_reason": None,
                   "findings_count": 1, "ended": "2026-01-01T00:00:00Z"}
            res = notifier.notify_run(
                eng, rec, run_log=["\x1b[33mBearer abc123SECRETtokenVALUE0000\x1b[0m"],
                config={"webhook_url": "https://h.example/hook", "payload_template": None,
                        "notify_on": None, "min_severity": "high", "timeout": 5},
                post=fake_post)
            self.assertTrue(res.sent)
            blob = json.dumps(captured["payload"])
            self.assertNotIn("hunter2SuperSecret", blob)      # finding title secret
            self.assertNotIn("abc123SECRETtokenVALUE", blob)  # run_log secret
            self.assertIn("sqli", blob)                       # class still reported
            self.assertEqual(captured["payload"]["findings_count"], 1)

    def test_outcome_filter_skips(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = pathlib.Path(tmp) / "eng"
            (eng / "runtime").mkdir(parents=True)
            res = notifier.notify_run(
                eng, {"outcome": "clean-tested"},
                config={"webhook_url": "https://h.example/hook", "payload_template": None,
                        "notify_on": ["failed", "produced-findings"], "min_severity": "high",
                        "timeout": 5},
                post=lambda u, p: (True, "HTTP 200"))
            self.assertTrue(res.skipped)
            self.assertIn("notify_on", res.reason)

    def test_post_failure_never_raises(self):
        def boom(url, payload):
            raise RuntimeError("network down")

        with tempfile.TemporaryDirectory() as tmp:
            eng = pathlib.Path(tmp) / "eng"
            (eng / "runtime").mkdir(parents=True)
            res = notifier.notify_run(
                eng, {"outcome": "failed"},
                config={"webhook_url": "https://h.example/hook", "payload_template": None,
                        "notify_on": None, "min_severity": "high", "timeout": 5},
                post=boom)
            self.assertFalse(res.sent)
            self.assertIn("network down", res.reason)


class TestCollector(unittest.TestCase):
    def test_tee_forwards_and_captures(self):
        seen = []
        c = notifier.Collector(maxlines=3)
        emit = c.tee(seen.append)
        for i in range(5):
            emit(f"line {i}")
        self.assertEqual(len(seen), 5)             # downstream got every line
        self.assertEqual(c.lines, ["line 2", "line 3", "line 4"])  # bounded tail


if __name__ == "__main__":
    unittest.main()
