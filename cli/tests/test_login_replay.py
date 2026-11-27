"""Tests for Feature 2 — declarative login-recipe replay with a liveness gate (login_replay.py).

Covers:
  • validate_recipe: steps + a REQUIRED auth_check liveness assertion.
  • ${var} substitution + stdlib CSRF extraction.
  • liveness_check (must_contain / must_not_contain / status).
  • refresh_identity gated by liveness: a LIVE current session skips the replay (fresh), a STALE
    one replays + confirms + persists the refreshed cookie into auth.env + creds (refreshed), a
    browser step with no backend degrades (needs-browser), a replay that does not restore liveness
    is a failure (failed).
  • refresh_all: an identity with no recipe is reported skipped.
  • load_recipes shape tolerance.

The HTTP client is injected (FakeClient) — no network.
"""
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # cli/

from redstrike_cli import accounts  # noqa: E402
from redstrike_cli import login_replay as lr  # noqa: E402


class _R:
    def __init__(self, status, text):
        self.status = status
        self.text = text


class FakeClient:
    """A scriptable client: the login POST makes it 'logged in'; the auth_check GET returns a page
    whose liveness depends on being logged in this session OR carrying the fresh cookie."""

    def __init__(self, *, csrf="tok123", login_works=True, fresh_cookie="session=FRESH"):
        self.csrf = csrf
        self.login_works = login_works
        self.fresh_cookie = fresh_cookie
        self.logged_in = False
        self.manual_cookie = None
        self.posts = []

    def set_session(self, cookie=None, headers=None):
        self.manual_cookie = cookie

    def get(self, url, headers=None):
        if "account" in url:
            live = (self.logged_in and self.login_works) or (self.manual_cookie == self.fresh_cookie)
            return _R(200, "Welcome — Sign out" if live else "Please Sign in")
        return _R(200, f'<form><input name="csrf_token" value="{self.csrf}"></form>')

    def post(self, url, data=None, headers=None):
        self.posts.append(data)
        self.logged_in = True
        return _R(302 if self.login_works else 401, "")

    def snapshot(self):
        return {"cookie": self.fresh_cookie, "headers": {}}


RECIPE = {
    "id": "userA",
    "steps": [
        {"action": "get", "url": "${BASE_URL}/login"},
        {"action": "extract_csrf", "from": "input[name=csrf_token]", "save_as": "CSRF"},
        {"action": "post", "url": "${BASE_URL}/login",
         "data": {"user": "${IDENTITY}", "password": "${PASSWORD}", "csrf_token": "${CSRF}"},
         "expect_status": [200, 302]},
    ],
    "auth_check": {"url": "${BASE_URL}/account", "must_contain": "Sign out", "must_not_contain": "Sign in"},
}


def _eng(tmp, *, cookie="session=STALE"):
    eng = pathlib.Path(tmp) / "eng"
    (eng / "runtime").mkdir(parents=True)
    acct = accounts.build_account(id="userA", identity="alice@t.com", password="pw-123456", cookie=cookie)
    acct["base_url"] = "https://x.com"
    accounts.save_creds(eng, {"engagement": "eng", "accounts": [acct]})
    return eng


class TestValidation(unittest.TestCase):
    def test_requires_auth_check_liveness(self):
        with self.assertRaises(lr.RecipeError):
            lr.validate_recipe({"steps": [{"action": "get", "url": "/x"}]})  # no auth_check
        with self.assertRaises(lr.RecipeError):
            lr.validate_recipe({"steps": [{"action": "get", "url": "/x"}],
                                "auth_check": {"url": "/a"}})  # no must_contain/not
        lr.validate_recipe(RECIPE)  # valid

    def test_rejects_bad_action(self):
        with self.assertRaises(lr.RecipeError):
            lr.validate_recipe({"steps": [{"action": "delete", "url": "/x"}],
                                "auth_check": {"url": "/a", "must_contain": "ok"}})


class TestPrimitives(unittest.TestCase):
    def test_substitute(self):
        out = lr.substitute({"u": "${IDENTITY}", "p": "x/${CSRF}"}, {"IDENTITY": "a@b", "CSRF": "zzz"})
        self.assertEqual(out, {"u": "a@b", "p": "x/zzz"})

    def test_extract_csrf(self):
        html = '<input name="csrf_token" value="ABC123">'
        self.assertEqual(lr.extract_csrf_value(html, "input[name=csrf_token]"), "ABC123")
        self.assertEqual(lr.extract_csrf_value(html, "csrf_token"), "ABC123")
        self.assertIsNone(lr.extract_csrf_value(html, "input[name=other]"))

    def test_liveness_check(self):
        ac = {"url": "/account", "must_contain": "Sign out", "must_not_contain": "Sign in"}
        self.assertTrue(lr.liveness_check(_live_client("Sign out welcome"), ac))
        self.assertFalse(lr.liveness_check(_live_client("Please Sign in"), ac))
        self.assertFalse(lr.liveness_check(_live_client("Sign out", status=500), ac))

    def test_vars_from_account(self):
        acct = accounts.build_account(id="u", identity="a@b", password="pw-123456", cookie="c=1")
        acct["base_url"] = "https://x.com"
        v = lr.vars_from_account(acct)
        self.assertEqual(v["IDENTITY"], "a@b")
        self.assertEqual(v["PASSWORD"], "pw-123456")
        self.assertEqual(v["BASE_URL"], "https://x.com")
        self.assertEqual(v["COOKIE"], "c=1")


def _live_client(body, status=200):
    class _C:
        def get(self, url, headers=None):
            return _R(status, body)
    return _C()


import base64 as _b64  # noqa: E402
import time as _time   # noqa: E402


def _mint_jwt(exp, *, extra=None):
    """Mint an UNSIGNED test JWT (header.payload.sig) whose payload carries `exp`. Test material only."""
    def _seg(d):
        return _b64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    payload = {"sub": "u"}
    if exp is not None:
        payload["exp"] = int(exp)
    if extra:
        payload.update(extra)
    return f"{_seg({'alg': 'RS256', 'typ': 'JWT'})}.{_seg(payload)}.sig"


class TestJwtExpPreflight(unittest.TestCase):
    """MED-5 — cheap session-liveness preflight: decode a JWT exp with zero network, and on expiry
    emit a clear re-capture result instead of failing opaquely on a 401/403."""

    def test_decode_jwt_exp_bare_and_in_cookie_blob(self):
        jwt = _mint_jwt(2_000_000_000)
        self.assertEqual(lr.decode_jwt_exp(jwt), 2_000_000_000)
        # a JWT embedded in a cookie blob (Authorization=...) is still found
        blob = f"20min-Session=opaquevalue; Authorization={jwt}"
        self.assertEqual(lr.decode_jwt_exp(blob), 2_000_000_000)

    def test_decode_jwt_exp_rejects_garbage(self):
        for bad in ("", None, "not-a-jwt", "session=plainopaquecookie", _mint_jwt(None),
                    "eyJ.only.two"):
            self.assertIsNone(lr.decode_jwt_exp(bad))

    def test_jwt_session_status_bands(self):
        now = 1_000_000.0
        self.assertEqual(lr.jwt_session_status(_mint_jwt(now + 3600), now=now), lr.LIVE)
        self.assertEqual(lr.jwt_session_status(_mint_jwt(now + 10), now=now, skew=60), lr.EXPIRING)
        self.assertEqual(lr.jwt_session_status(_mint_jwt(now - 1), now=now), lr.EXPIRED)
        self.assertEqual(lr.jwt_session_status("opaque-cookie", now=now), lr.UNKNOWN)

    def test_preflight_expired_jwt_flags_recapture_zero_network(self):
        acct = {"session": {"cookie": f"Authorization={_mint_jwt(_time.time() - 5)}"}}
        pre = lr.session_preflight(acct)          # no client passed → must NOT need one
        self.assertEqual(pre.status, lr.EXPIRED)
        self.assertEqual(pre.source, "jwt-exp")
        self.assertTrue(pre.needs_recapture())
        self.assertIn("RE-CAPTURE", pre.reason)

    def test_preflight_live_jwt_ok(self):
        acct = {"secret": {"token": _mint_jwt(_time.time() + 3600)}}
        pre = lr.session_preflight(acct)
        self.assertTrue(pre.ok())
        self.assertEqual(pre.source, "jwt-exp")

    def test_preflight_opaque_falls_back_to_probe(self):
        acct = {"session": {"cookie": "session=OPAQUE"}}
        ac = {"url": "/account", "must_contain": "Sign out"}
        self.assertTrue(lr.session_preflight(acct, auth_check=ac,
                                             client=_live_client("Sign out")).ok())
        pre = lr.session_preflight(acct, auth_check=ac, client=_live_client("Please Sign in"))
        self.assertEqual(pre.status, lr.EXPIRED)
        self.assertEqual(pre.source, "probe")

    def test_preflight_unknown_when_nothing_to_check(self):
        pre = lr.session_preflight({"session": {"cookie": "session=OPAQUE"}})
        self.assertEqual(pre.status, lr.UNKNOWN)
        self.assertEqual(pre.source, "none")

    def test_refresh_expired_jwt_skips_wasted_probe_and_replays(self):
        # The current-session probe WOULD report live (fresh_cookie == the stored cookie), so without
        # the JWT fast-path this returns FRESH. With it, the expired exp forces a stale → REFRESHED.
        expired = f"Authorization={_mint_jwt(_time.time() - 5)}"
        with tempfile.TemporaryDirectory() as tmp:
            eng = _eng(tmp, cookie=expired)
            acct = accounts.load_creds(eng)["accounts"][0]
            r = lr.refresh_identity(eng, acct, RECIPE,
                                    client_factory=lambda: FakeClient(fresh_cookie=expired))
            self.assertEqual(r.status, lr.REFRESHED)


class TestRefreshGate(unittest.TestCase):
    def test_stale_refreshes_and_persists(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = _eng(tmp, cookie="session=STALE")
            acct = accounts.load_creds(eng)["accounts"][0]
            r = lr.refresh_identity(eng, acct, RECIPE, client_factory=lambda: FakeClient())
            self.assertEqual(r.status, lr.REFRESHED)
            self.assertTrue(r.cookie_set)
            # persisted into auth.env + creds.json
            envtxt = (eng / "runtime" / "auth.env").read_text(encoding="utf-8")
            self.assertIn("session=FRESH", envtxt)
            stored = accounts.load_creds(eng)["accounts"][0]
            self.assertEqual(stored["session"]["cookie"], "session=FRESH")

    def test_live_session_skips_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = _eng(tmp, cookie="session=FRESH")  # current session already live
            acct = accounts.load_creds(eng)["accounts"][0]
            fc = FakeClient()
            r = lr.refresh_identity(eng, acct, RECIPE, client_factory=lambda: fc)
            self.assertEqual(r.status, lr.FRESH)
            self.assertEqual(fc.posts, [])  # no login attempt — gated by liveness

    def test_browser_step_degrades(self):
        recipe = dict(RECIPE)
        recipe = json.loads(json.dumps(RECIPE))
        recipe["steps"].append({"action": "browser", "url": "${BASE_URL}/login"})
        with tempfile.TemporaryDirectory() as tmp:
            eng = _eng(tmp, cookie="session=STALE")
            acct = accounts.load_creds(eng)["accounts"][0]
            r = lr.refresh_identity(eng, acct, recipe, client_factory=lambda: FakeClient())
            self.assertEqual(r.status, lr.NEEDS_BROWSER)
            self.assertIn("browser-session.md", r.reason)

    def test_failed_when_liveness_not_restored(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = _eng(tmp, cookie="session=STALE")
            acct = accounts.load_creds(eng)["accounts"][0]
            # login_works=False → post returns 401 and the auth_check never shows "Sign out"
            r = lr.refresh_identity(eng, acct, RECIPE,
                                    client_factory=lambda: FakeClient(login_works=False))
            self.assertEqual(r.status, lr.FAILED)

    def test_refresh_all_skips_identity_without_recipe(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = _eng(tmp)
            # no login_recipes.json present
            results = lr.refresh_all(eng, client_factory=lambda: FakeClient())
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].status, lr.SKIPPED)


class TestHttpOnlyClient(unittest.TestCase):
    """SSRF / local-file hardening — the stdlib login-replay client is http(s)-only. A login recipe
    is replayed in the CLI process, OUTSIDE the engine's scope gate, so a step URL (or a redirect
    target) must never reach a file:// / ftp:// / data: scheme (local-file read / SSRF)."""

    def test_non_http_scheme_steps_refused(self):
        client = lr.UrllibClient()
        for bad in ("file:///etc/passwd", "ftp://host/secret", "data:text/plain,hi", "gopher://x/"):
            with self.assertRaises(lr.RecipeError):
                client.get(bad)
        with self.assertRaises(lr.RecipeError):
            client.post("file:///etc/passwd", data={"a": "b"})

    def test_opener_omits_file_and_ftp_handlers(self):
        import urllib.request
        client = lr.UrllibClient()
        for h in client._opener.handlers:
            self.assertNotIsInstance(h, urllib.request.FileHandler)
            self.assertNotIsInstance(h, urllib.request.FTPHandler)

    def test_http_step_builds_and_opens_without_network(self):
        # The normal http(s) flow is unchanged: the request is built and handed to the opener. The
        # opener is mocked so NO real fetch happens.
        client = lr.UrllibClient()

        class _FakeHTTPResp:
            status = 200

            def read(self):
                return b"LOGIN-OK"

        class _FakeOpener:
            def __init__(self):
                self.opened = []

            def open(self, req, timeout=None):
                self.opened.append(req.full_url)
                return _FakeHTTPResp()

        fake = _FakeOpener()
        client._opener = fake
        resp = client.get("https://in-scope.example.com/login")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.text, "LOGIN-OK")
        self.assertEqual(fake.opened, ["https://in-scope.example.com/login"])


class TestLoadRecipes(unittest.TestCase):
    def test_shapes(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = pathlib.Path(tmp) / "eng"
            eng.mkdir()
            (eng / lr.RECIPES_NAME).write_text(json.dumps({"recipes": [RECIPE]}), encoding="utf-8")
            self.assertIn("userA", lr.load_recipes(eng))
            (eng / lr.RECIPES_NAME).write_text(json.dumps({"userB": {"steps": []}}), encoding="utf-8")
            r = lr.load_recipes(eng)
            self.assertIn("userB", r)
            self.assertEqual(r["userB"]["id"], "userB")

    def test_absent_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            eng = pathlib.Path(tmp) / "eng"
            eng.mkdir()
            self.assertEqual(lr.load_recipes(eng), {})


if __name__ == "__main__":
    unittest.main()
