"""Tests for QW-5b — curlparse: a browser 'Copy as cURL' paste → accounts.build_account() fields.

Covers:
  • a realistic Chrome 'Copy as cURL (bash)' paste (multi-line '\\'-continuation, single quotes,
    many headers, a Cookie header, an Authorization bearer) parses into url/base_url/cookie/token.
  • account_fields() keeps the session material (cookie, bearer, custom x-* header) and DROPS the
    per-request browser-noise headers (user-agent / accept* / sec-*).
  • cookie via -b, basic auth via -u, --request method, --data → POST, --header=value form.
  • Windows cmd form ('^'-continuation, double quotes) and $'...' ANSI-C quoting.
  • garbage / empty input never raises (empty url → caller rejects).

Stdlib only; no network, no filesystem.
"""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # cli/

from redstrike_cli import curlparse  # noqa: E402

CHROME_BASH = r"""curl 'https://app.example.com/api/v2/me' \
  -H 'accept: application/json' \
  -H 'accept-language: en-US,en;q=0.9' \
  -H 'authorization: Bearer eyJhbGciOiJIUzI1NiJ9.Zm9v.sig' \
  -H 'cookie: sessionid=ABC123; csrftoken=XYZ789' \
  -H 'x-csrf-token: XYZ789' \
  -H 'sec-fetch-mode: cors' \
  -H 'user-agent: Mozilla/5.0' \
  --compressed"""


class TestChromeBashPaste(unittest.TestCase):
    def setUp(self):
        self.pc = curlparse.parse_curl(CHROME_BASH)

    def test_url_and_base_url(self):
        self.assertEqual(self.pc.url, "https://app.example.com/api/v2/me")
        self.assertEqual(self.pc.base_url, "https://app.example.com")

    def test_cookie_and_bearer_extracted(self):
        self.assertEqual(self.pc.cookie, "sessionid=ABC123; csrftoken=XYZ789")
        self.assertEqual(self.pc.token, "eyJhbGciOiJIUzI1NiJ9.Zm9v.sig")
        # Authorization is consumed into .token, NOT left as a header
        self.assertNotIn("authorization", {k.lower() for k in self.pc.headers})
        # Cookie is consumed into .cookie, NOT left as a header
        self.assertNotIn("cookie", {k.lower() for k in self.pc.headers})

    def test_parse_keeps_every_header_faithfully(self):
        names = {k.lower() for k in self.pc.headers}
        self.assertIn("x-csrf-token", names)
        self.assertIn("user-agent", names)       # faithful parse keeps noise too
        self.assertIn("sec-fetch-mode", names)

    def test_account_fields_projection_drops_noise_keeps_session(self):
        f = self.pc.account_fields()
        self.assertEqual(f["cookie"], "sessionid=ABC123; csrftoken=XYZ789")
        self.assertEqual(f["token"], "eyJhbGciOiJIUzI1NiJ9.Zm9v.sig")
        self.assertEqual(f["base_url"], "https://app.example.com")
        kept = {k.lower() for k in f["headers"]}
        self.assertIn("x-csrf-token", kept)       # a custom/auth header survives
        self.assertNotIn("user-agent", kept)      # browser noise dropped
        self.assertNotIn("accept", kept)
        self.assertNotIn("sec-fetch-mode", kept)


class TestFlagForms(unittest.TestCase):
    def test_cookie_via_b_flag(self):
        pc = curlparse.parse_curl("curl https://x.com/ -b 'a=1; b=2'")
        self.assertEqual(pc.cookie, "a=1; b=2")

    def test_basic_auth_via_u(self):
        pc = curlparse.parse_curl("curl https://x.com/ -u alice:s3cret")
        self.assertEqual(pc.basic_user, "alice")
        self.assertEqual(pc.basic_pass, "s3cret")
        f = pc.account_fields()
        self.assertEqual(f["identity"], "alice")
        self.assertEqual(f["password"], "s3cret")

    def test_request_method_and_data_defaults_post(self):
        pc = curlparse.parse_curl("curl https://x.com/api -X POST --data-raw '{\"q\":1}'")
        self.assertEqual(pc.method, "POST")
        self.assertEqual(pc.data, '{"q":1}')

    def test_data_flag_implies_post(self):
        pc = curlparse.parse_curl("curl https://x.com/ --data 'k=v'")
        self.assertEqual(pc.method, "POST")

    def test_header_equals_form(self):
        pc = curlparse.parse_curl("curl https://x.com/ --header='X-Api-Key: topsecret'")
        self.assertEqual(pc.headers.get("X-Api-Key"), "topsecret")

    def test_non_bearer_authorization_kept_as_header(self):
        pc = curlparse.parse_curl("curl https://x.com/ -H 'Authorization: Basic dXNlcjpwdw=='")
        self.assertEqual(pc.token, "")
        self.assertEqual(pc.headers.get("Authorization"), "Basic dXNlcjpwdw==")

    def test_no_url_token_not_confused_by_flag_values(self):
        # -o takes an arg; its value must NOT be mistaken for the URL
        pc = curlparse.parse_curl("curl -o out.json https://real.example/x")
        self.assertEqual(pc.url, "https://real.example/x")


class TestOtherShellForms(unittest.TestCase):
    def test_windows_cmd_caret_continuation_double_quotes(self):
        cmd = ('curl "https://x.com/api" ^\n'
               '  -H "cookie: sid=WIN123" ^\n'
               '  -H "x-token: abc"')
        pc = curlparse.parse_curl(cmd)
        self.assertEqual(pc.url, "https://x.com/api")
        self.assertEqual(pc.cookie, "sid=WIN123")
        self.assertEqual(pc.headers.get("x-token"), "abc")

    def test_ansi_c_quoting(self):
        pc = curlparse.parse_curl("curl 'https://x.com/' -H $'cookie: sid=ANSI1'")
        self.assertEqual(pc.cookie, "sid=ANSI1")

    def test_bare_url_without_curl_prefix(self):
        pc = curlparse.parse_curl("https://x.com/path?q=1")
        self.assertEqual(pc.base_url, "https://x.com")


class TestRobustness(unittest.TestCase):
    def test_empty_and_garbage_never_raise(self):
        for bad in ("", "   ", None, "curl", "not a curl at all", "curl -H"):
            pc = curlparse.parse_curl(bad)
            self.assertEqual(pc.url, "")
            self.assertEqual(pc.account_fields(), {})


if __name__ == "__main__":
    unittest.main()
