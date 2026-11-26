"""Tests for QW-5a/QW-5b — the `redstrike session` CLI (status + import).

Covers:
  • `session status`: LIVE vs EXPIRED vs UNKNOWN from a crafted JWT `exp` (offline, zero network),
    with the correct exit code (1 iff an identity needs re-capture), and the empty-accounts case.
  • `session import`: a browser 'Copy as cURL' paste lands in runtime/creds.json (cookie + bearer),
    (re)materializes runtime/auth.env, and the echo is REDACTED (raw cookie/bearer never printed).
  • import → status round-trip: an imported live-JWT bearer reads back LIVE.

Driven end-to-end through __main__.main() with a tempdir repo; stdlib only.
"""
import base64
import io
import json
import pathlib
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # cli/

from redstrike_cli import accounts  # noqa: E402
from redstrike_cli.__main__ import main  # noqa: E402


def _mint_jwt(exp) -> str:
    """An UNSIGNED test JWT (header.payload.sig) carrying `exp`. Test material only."""
    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{seg({'alg': 'HS256', 'typ': 'JWT'})}.{seg({'sub': 'u', 'exp': int(exp)})}.sig"


def _run(repo, *argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["--repo", str(repo), "--no-color", "--no-banner", *argv])
    return rc, buf.getvalue()


def _mk_engagement(repo, eid="acme-eng"):
    eng = repo / "engagements" / eid
    (eng / "runtime").mkdir(parents=True)
    return eng, eid


class TestSessionStatus(unittest.TestCase):
    def _store_cookie(self, eng, cookie, acct_id="userA"):
        acct = accounts.build_account(id=acct_id, role="user", identity="a@b.com", cookie=cookie)
        accounts.save_creds(eng, {"engagement": eng.name, "accounts": [acct]})

    def test_live_jwt_is_live_rc0(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            eng, eid = _mk_engagement(repo)
            self._store_cookie(eng, f"sid=x; Authorization={_mint_jwt(time.time() + 3600)}")
            rc, out = _run(repo, "session", "status", eid)
            self.assertEqual(rc, 0, out)
            self.assertIn("LIVE", out)
            self.assertIn("left", out)              # time-remaining rendered

    def test_expired_jwt_needs_recapture_rc1(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            eng, eid = _mk_engagement(repo)
            self._store_cookie(eng, f"sid=x; Authorization={_mint_jwt(time.time() - 120)}")
            rc, out = _run(repo, "session", "status", eid)
            self.assertEqual(rc, 1, out)            # non-zero: an identity needs re-capture
            self.assertIn("EXPIRED", out)
            self.assertIn("re-capture", out.lower())

    def test_opaque_session_is_unknown_rc0(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            eng, eid = _mk_engagement(repo)
            self._store_cookie(eng, "sessionid=OPAQUEVALUE")
            rc, out = _run(repo, "session", "status", eid)
            self.assertEqual(rc, 0, out)
            self.assertIn("UNKNOWN", out)
            self.assertIn("offline", out.lower())

    def test_no_accounts_is_noop_rc0(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            _, eid = _mk_engagement(repo)
            rc, out = _run(repo, "session", "status", eid)
            self.assertEqual(rc, 0, out)
            self.assertIn("no test accounts", out)

    def test_missing_engagement_rc1(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            (repo / "engagements").mkdir()
            rc, out = _run(repo, "session", "status", "does-not-exist")
            self.assertEqual(rc, 1)
            self.assertIn("not found", out)


IMPORT_CURL_TMPL = (
    "curl 'https://app.example.com/api/v2/me' "
    "-H 'accept: application/json' "
    "-H 'user-agent: Mozilla/5.0' "
    "-H 'authorization: Bearer {jwt}' "
    "-H 'cookie: sessionid=SECRETCOOKIE123; csrftoken=TOK' "
    "-H 'x-csrf-token: TOK' "
    "--compressed"
)


class TestSessionImport(unittest.TestCase):
    def test_import_persists_redacts_and_materializes(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            eng, eid = _mk_engagement(repo)
            jwt = _mint_jwt(time.time() + 3600)
            curl = IMPORT_CURL_TMPL.format(jwt=jwt)
            rc, out = _run(repo, "session", "import", eid, curl, "--id", "browserA", "--role", "user")
            self.assertEqual(rc, 0, out)

            # creds.json carries the cookie + bearer, base_url derived
            creds = accounts.load_creds(eng)
            acct = next(a for a in creds["accounts"] if a["id"] == "browserA")
            self.assertEqual(acct["session"]["cookie"], "sessionid=SECRETCOOKIE123; csrftoken=TOK")
            self.assertEqual(acct["secret"]["token"], jwt)
            self.assertEqual(acct["base_url"], "https://app.example.com")
            # browser-noise header dropped, custom header kept
            self.assertIn("x-csrf-token", acct["session"]["headers"])
            self.assertNotIn("user-agent", acct["session"]["headers"])

            # auth.env materialized under runtime/ (gitignored)
            env = (eng / "runtime" / "auth.env").read_text(encoding="utf-8")
            self.assertIn("sessionid=SECRETCOOKIE123", env)  # the clear session for executors only

            # the ECHO must be redacted — the raw cookie value + full bearer never printed
            self.assertIn("session imported", out)
            self.assertIn("https://app.example.com", out)
            self.assertNotIn("SECRETCOOKIE123", out)
            self.assertNotIn(jwt, out)
            self.assertIn("set (", out)                      # masked cookie hint

    def test_import_defaults_id_to_imported(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            eng, eid = _mk_engagement(repo)
            curl = IMPORT_CURL_TMPL.format(jwt=_mint_jwt(time.time() + 3600))
            rc, out = _run(repo, "session", "import", eid, curl)
            self.assertEqual(rc, 0, out)
            self.assertTrue(any(a["id"] == "imported" for a in accounts.load_creds(eng)["accounts"]))

    def test_import_without_curl_errors(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            _, eid = _mk_engagement(repo)
            rc, out = _run(repo, "session", "import", eid)
            self.assertEqual(rc, 2)
            self.assertIn("needs the cURL", out)

    def test_import_no_session_material_errors(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            _, eid = _mk_engagement(repo)
            rc, out = _run(repo, "session", "import", eid, "curl 'https://x.com/' -H 'accept: */*'")
            self.assertEqual(rc, 2)
            self.assertIn("no session material", out)

    def test_import_then_status_round_trip_live(self):
        with tempfile.TemporaryDirectory() as d:
            repo = pathlib.Path(d)
            _, eid = _mk_engagement(repo)
            curl = IMPORT_CURL_TMPL.format(jwt=_mint_jwt(time.time() + 3600))
            rc, _ = _run(repo, "session", "import", eid, curl, "--id", "browserA")
            self.assertEqual(rc, 0)
            rc, out = _run(repo, "session", "status", eid)
            self.assertEqual(rc, 0, out)
            self.assertIn("LIVE", out)


if __name__ == "__main__":
    unittest.main()
