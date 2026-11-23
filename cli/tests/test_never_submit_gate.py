import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # cli/

from redstrike_cli.hooks import never_submit_gate as g  # noqa: E402

BB_SCOPE = {"in_scope": {"domains": ["*.acme.com"]}, "mission": "bug-bounty"}
PENTEST_SCOPE = {"in_scope": {"domains": ["*.acme.com"]}}


class _Eng:
    def __enter__(self):
        self._td = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self._td.name) / "eng"
        (self.dir / "runtime").mkdir(parents=True)
        (self.dir / "submissions").mkdir()
        return self.dir

    def __exit__(self, *a):
        self._td.cleanup()


def _dec(eng, scope, content, name="sub1.md"):
    ti = {"file_path": str(eng / "submissions" / name), "content": content}
    return g.evaluate("Write", ti, eng, scope, eng)["decision"]


class TestBugBountyDetection(unittest.TestCase):
    def test_mission_marker_is_bug_bounty(self):
        self.assertTrue(g.is_bug_bounty(None, {"mission": "bug-bounty"}))
        self.assertTrue(g.is_bug_bounty(None, {"mission": "Bug Bounty"}))
        self.assertTrue(g.is_bug_bounty(None, {"rules": {"mission": "bug-bounty"}}))

    def test_program_scope_json_is_bug_bounty(self):
        with _Eng() as eng:
            (eng / "program_scope.json").write_text("{}")
            self.assertTrue(g.is_bug_bounty(eng, PENTEST_SCOPE))

    def test_pentest_is_not_bug_bounty(self):
        self.assertFalse(g.is_bug_bounty(None, PENTEST_SCOPE))
        with _Eng() as eng:  # no program_scope.json, no mission marker
            self.assertFalse(g.is_bug_bounty(eng, PENTEST_SCOPE))


class TestSignalsAndChainLanguage(unittest.TestCase):
    def test_detects_each_never_submit_signal(self):
        cases = {
            "missing-headers-alone": "The response is missing the Content-Security-Policy header.",
            "self-xss": "This is a self-XSS in the console input.",
            "open-redirect-alone": "Open redirect on /go?url=.",
            "cors-wildcard-no-impact": "CORS returns Access-Control-Allow-Origin: * wildcard.",
            "blind-dns-only-ssrf": "Blind SSRF confirmed via OOB DNS callback (interactsh).",
            "clickjacking-no-impact": "The page is vulnerable to clickjacking.",
            "version-disclosure": "Server banner version disclosure of nginx 1.1.",
        }
        for want, text in cases.items():
            names = [n for n, _ in g.detect_never_submit(text)]
            self.assertIn(want, names, f"{want} not detected in: {text}")

    def test_chain_language_detected(self):
        for t in ["chained to ATO", "leads to account takeover", "combined with CSRF",
                  "escalates to RCE", "see chain-003", "which allows reading tokens"]:
            self.assertTrue(g.has_chain_language(t), t)

    def test_benign_text_has_no_signal(self):
        self.assertEqual(g.detect_never_submit("Stored XSS executes in the admin view."), [])


class TestEvaluateScoping(unittest.TestCase):
    def test_bug_bounty_bare_signal_denies(self):
        with _Eng() as eng:
            self.assertEqual(_dec(eng, BB_SCOPE, "# Open redirect on /go?url= — external domain."),
                             "deny")

    def test_bug_bounty_signal_with_chain_language_passes(self):
        with _Eng() as eng:
            self.assertEqual(
                _dec(eng, BB_SCOPE,
                     "Open redirect chained via OAuth redirect_uri leads to account takeover (ATO)."),
                "pass")

    def test_pentest_never_fires_even_with_signal(self):
        # the whole point: outside bug-bounty, an informational finding write is never touched
        with _Eng() as eng:
            self.assertEqual(
                _dec(eng, PENTEST_SCOPE, "Missing Content-Security-Policy header; clickjacking possible."),
                "pass")

    def test_program_scope_json_enables_the_gate(self):
        with _Eng() as eng:
            (eng / "program_scope.json").write_text("{}")
            self.assertEqual(
                _dec(eng, PENTEST_SCOPE, "CORS wildcard: Access-Control-Allow-Origin: *."),
                "deny")

    def test_only_fires_on_submission_drafts(self):
        with _Eng() as eng:
            # a non-submission file in a bug-bounty engagement is not touched
            ti = {"file_path": str(eng / "notes.md"), "content": "self-XSS here"}
            self.assertEqual(g.evaluate("Write", ti, eng, BB_SCOPE, eng)["decision"], "pass")

    def test_clean_submission_passes(self):
        with _Eng() as eng:
            self.assertEqual(
                _dec(eng, BB_SCOPE,
                     "IDOR: user A reads user B's invoice via GET /api/invoices/{id}."),
                "pass")

    def test_deny_reason_names_the_anchor(self):
        with _Eng() as eng:
            ti = {"file_path": str(eng / "submissions" / "s.md"),
                  "content": "Blind SSRF via webhook_url, OOB DNS only."}
            d = g.evaluate("Write", ti, eng, BB_SCOPE, eng)
            self.assertEqual(d["decision"], "deny")
            self.assertIn("metadata", d["reason"].lower())  # the anchor mentions cloud metadata reach

    def test_non_write_tool_passes(self):
        with _Eng() as eng:
            self.assertEqual(g.evaluate("Bash", {"command": "x"}, eng, BB_SCOPE, eng)["decision"], "pass")


if __name__ == "__main__":
    unittest.main()
