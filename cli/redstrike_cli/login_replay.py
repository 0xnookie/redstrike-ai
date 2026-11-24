"""Declarative login-recipe replay — deterministically refresh an EXPIRING session, no browser each run.

A long engagement's test-account session expires mid-run. ``accounts.materialize()`` writes the
stored session into ``runtime/auth.env`` once, but it cannot MINT a fresh one — so when the cookie
goes stale the executors silently start hitting ``/login``. Re-driving a real browser every run to
re-authenticate is slow, noisy and lockout-risky (``browser-session.md``). This module closes that
gap: a per-identity declarative login RECIPE (JSON) that a deterministic HTTP player replays to
refresh the session into ``runtime/auth.env`` + the cookie-jar — and ONLY when it is actually stale.

THE RECIPE  (``<engagement>/login_recipes.json``, operator-authored, gitignored under engagements/)
    { "recipes": [ {
        "id": "userA",                         # matches an accounts/creds.json identity id
        "steps": [
          {"action": "get",  "url": "${BASE_URL}/login"},
          {"action": "extract_csrf", "from": "input[name=csrf_token]", "save_as": "CSRF"},
          {"action": "post", "url": "${BASE_URL}/login",
           "data": {"user": "${IDENTITY}", "password": "${PASSWORD}", "csrf_token": "${CSRF}"},
           "expect_status": [200, 302]},
          {"action": "browser", "url": "${BASE_URL}/login"}   # OPTIONAL — see "Browser steps" below
        ],
        "auth_check": {"url": "${BASE_URL}/account",
                       "must_contain": "Sign out", "must_not_contain": "Sign in"}
    } ] }

  * ``${var}`` substitution is seeded from the stored creds (the SAME suffixes ``auth.env`` exposes:
    ``IDENTITY``, ``PASSWORD``, ``BEARER``, ``API_KEY``, ``COOKIE``, ``BASE_URL``, ``ROLE``,
    ``TENANT``) plus any value a step extracts (``extract_csrf`` → ``save_as``).
  * ``auth_check`` is a REQUIRED session-LIVENESS assertion (``must_contain`` / ``must_not_contain``).

THE LIVENESS GATE  (refresh only if stale — never unconditionally)
    ``refresh_identity`` runs the ``auth_check`` probe against the CURRENT stored session FIRST. If it
    is still live, the recipe is NOT replayed (status ``fresh``). Only a stale/absent session triggers
    a replay, and the SAME probe must pass against the NEW session before it is persisted — a replay
    that does not restore liveness is a ``failed`` refresh, not a false ``refreshed``.

BROWSER STEPS  (reference the existing backend; never hard-code one)
    This stdlib player drives the deterministic HTTP rungs (get / post / extract_csrf) only. A
    ``browser`` step degrades to redstrike's ``browser-drive`` capability — see
    ``skills/_contract/browser-session.md`` ("Deterministic session refresh (login recipe)"). When no
    browser backend is wired into the player, a reached ``browser`` step returns status
    ``needs-browser`` (the operator drives that one rung via the engagement's browser-drive backend,
    per the anti-automation ladder) rather than this module hard-coding a browser engine.

Stdlib only. The HTTP client is injectable (``client_factory=``) so the pure logic — substitution,
CSRF extraction, liveness evaluation, the refresh decision — is unit-tested without a network. A
refreshed session is persisted via ``accounts`` (creds.json → notebook projection → auth.env) and
the Netscape cookie-jar at ``runtime/cookies.txt`` (the jar ``browser-session.md`` documents reusing).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from . import accounts

RECIPES_NAME = "login_recipes.json"
COOKIE_JAR_REL = Path("runtime") / "cookies.txt"
BROWSER_CONTRACT = "skills/_contract/browser-session.md"

VALID_ACTIONS = frozenset({"get", "post", "extract_csrf", "browser"})

# Refresh outcomes.
FRESH = "fresh"             # the current session is still live — no replay performed
REFRESHED = "refreshed"     # the session was stale; the recipe replayed and restored liveness
FAILED = "failed"           # the replay ran but liveness did not come back (or a step errored)
NEEDS_BROWSER = "needs-browser"  # a browser step was reached and no browser backend is wired
SKIPPED = "skipped"         # the identity has no recipe


class RecipeError(Exception):
    """Invalid recipe structure or a failed deterministic step."""


class BrowserStepRequired(Exception):
    """A ``browser`` step was reached but no browser backend is available to the player."""


# --- recipe loading / validation ---------------------------------------------
def recipes_path(eng: Path) -> Path:
    return Path(eng) / RECIPES_NAME


def load_recipes(eng: Path) -> dict:
    """Return ``{identity_id: recipe}`` from ``<engagement>/login_recipes.json``. Tolerates several
    shapes: ``{"recipes": [ {id, ...} ]}``, ``{"recipes": {id: {...}}}``, a bare ``[ {id, ...} ]``,
    or a bare ``{id: {...}}``. Absent/malformed file ⇒ ``{}`` (no recipes)."""
    try:
        doc = json.loads(recipes_path(eng).read_text(encoding="utf-8"))
    except Exception:
        return {}
    out: dict = {}
    if isinstance(doc, dict) and "recipes" in doc:
        doc = doc["recipes"]
    if isinstance(doc, list):
        for r in doc:
            if isinstance(r, dict) and r.get("id"):
                out[str(r["id"])] = r
    elif isinstance(doc, dict):
        for k, v in doc.items():
            if isinstance(v, dict):
                v = dict(v)
                v.setdefault("id", k)
                out[str(k)] = v
    return out


def validate_recipe(recipe: dict) -> None:
    """Raise ``RecipeError`` unless the recipe has a ``steps`` list of valid actions AND an
    ``auth_check`` with at least one of ``must_contain`` / ``must_not_contain`` (the liveness
    assertion is mandatory — without it there is no deterministic way to decide 'stale')."""
    if not isinstance(recipe, dict):
        raise RecipeError("recipe must be a JSON object")
    steps = recipe.get("steps")
    if not isinstance(steps, list) or not steps:
        raise RecipeError("recipe must have a non-empty 'steps' list")
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            raise RecipeError(f"step {i} must be an object")
        action = step.get("action")
        if action not in VALID_ACTIONS:
            raise RecipeError(f"step {i} has invalid action {action!r}; valid: {sorted(VALID_ACTIONS)}")
        if action in ("get", "post") and not step.get("url"):
            raise RecipeError(f"step {i} ({action}) needs a 'url'")
        if action == "extract_csrf" and not step.get("from"):
            raise RecipeError(f"step {i} (extract_csrf) needs a 'from' selector")
    ac = recipe.get("auth_check")
    if not isinstance(ac, dict) or not ac.get("url"):
        raise RecipeError("recipe must declare an 'auth_check' with a 'url' (the liveness probe)")
    if not (ac.get("must_contain") or ac.get("must_not_contain")):
        raise RecipeError("auth_check needs at least one of 'must_contain' / 'must_not_contain'")


# --- ${var} substitution -----------------------------------------------------
_VAR = re.compile(r"\$\{(\w+)\}")


def substitute(template, vars_: dict):
    """Recursively replace ``${name}`` in strings (missing var → empty string)."""
    if isinstance(template, str):
        return _VAR.sub(lambda m: str(vars_.get(m.group(1), "")), template)
    if isinstance(template, dict):
        return {k: substitute(v, vars_) for k, v in template.items()}
    if isinstance(template, (list, tuple)):
        return [substitute(v, vars_) for v in template]
    return template


def vars_from_account(account: dict) -> dict:
    """Build the ``${var}`` namespace from a stored creds account — the SAME suffixes
    ``accounts.materialize`` exposes in auth.env, so a recipe reads what the executors read."""
    acct = account or {}
    secret = acct.get("secret") or {}
    session = acct.get("session") or {}
    out = {
        "ID": acct.get("id", ""),
        "ROLE": acct.get("role", ""),
        "TENANT": acct.get("tenant", ""),
        "BASE_URL": acct.get("base_url", ""),
        "IDENTITY": acct.get("identity", ""),
        "PASSWORD": secret.get("password", ""),
        "BEARER": secret.get("token", ""),
        "API_KEY": secret.get("api_key", ""),
        "COOKIE": session.get("cookie", ""),
    }
    return {k: v for k, v in out.items() if v}


# --- CSRF extraction (stdlib regex; no third-party parser) --------------------
def extract_csrf_value(html: str, selector: str):
    """Pull the ``value`` attribute of the element named by a simple ``input[name=foo]`` selector
    (or a bare field name). Stdlib-only. Returns None when not found."""
    if not html:
        return None
    name = selector
    m = re.match(r"\s*input\[name=[\"']?([\w.-]+)[\"']?\]\s*", selector or "")
    if m:
        name = m.group(1)
    name = (name or "").strip()
    if not name:
        return None
    pat1 = re.compile(
        rf"<input[^>]+name=[\"']?{re.escape(name)}[\"']?[^>]+value=[\"']([^\"']*)[\"']", re.IGNORECASE)
    hit = pat1.search(html)
    if hit:
        return hit.group(1)
    pat2 = re.compile(
        rf"<input[^>]+value=[\"']([^\"']*)[\"'][^>]+name=[\"']?{re.escape(name)}[\"']?", re.IGNORECASE)
    hit = pat2.search(html)
    return hit.group(1) if hit else None


# --- response helpers (duck-typed; works with urllib + fakes) ----------------
def _resp_text(resp) -> str:
    if resp is None:
        return ""
    t = getattr(resp, "text", None)
    if isinstance(t, str):
        return t
    if callable(t):
        try:
            return str(t())
        except Exception:
            return ""
    body = getattr(resp, "content", None) or getattr(resp, "body", None)
    if isinstance(body, bytes):
        return body.decode("utf-8", "replace")
    if isinstance(body, str):
        return body
    return ""


def _resp_status(resp):
    for attr in ("status", "status_code", "code"):
        v = getattr(resp, attr, None)
        if isinstance(v, int):
            return v
    return None


# --- the liveness probe + the player -----------------------------------------
def liveness_check(client, auth_check: dict) -> bool:
    """Probe session liveness: GET ``auth_check.url`` through ``client`` and apply the assertion
    (``must_contain`` present AND ``must_not_contain`` absent, and status < 400 when known).
    Any exception ⇒ not live (fail-safe)."""
    url = (auth_check or {}).get("url", "")
    if not url:
        return False
    try:
        resp = client.get(url)
    except Exception:
        return False
    text = _resp_text(resp)
    status = _resp_status(resp)
    if status is not None and status >= 400:
        return False
    mc = auth_check.get("must_contain")
    mnc = auth_check.get("must_not_contain")
    if mc and mc not in text:
        return False
    if mnc and mnc in text:
        return False
    return True


def play(recipe: dict, vars_: dict, client, *, allow_browser: bool = False) -> dict:
    """Execute the recipe's deterministic steps against ``client``, mutating ``vars_`` with any
    extracted values. Raises ``BrowserStepRequired`` on a ``browser`` step when ``allow_browser`` is
    False (no backend), and ``RecipeError`` on a step failure. Returns the final ``vars_``."""
    last_text = ""
    for i, raw in enumerate(recipe.get("steps", [])):
        action = raw.get("action")
        step = substitute(raw, vars_)
        if action == "get":
            resp = client.get(step["url"], headers=step.get("headers"))
            last_text = _resp_text(resp)
            _check_expect(step, resp, last_text, i)
        elif action == "post":
            resp = client.post(step["url"], data=step.get("data", {}), headers=step.get("headers"))
            last_text = _resp_text(resp)
            _check_expect(step, resp, last_text, i)
        elif action == "extract_csrf":
            val = extract_csrf_value(last_text, step.get("from", ""))
            if val is None:
                raise RecipeError(f"step {i}: CSRF '{step.get('from')}' not found in the last response")
            vars_[step.get("save_as", "CSRF")] = val
        elif action == "browser":
            if not allow_browser:
                raise BrowserStepRequired(
                    f"step {i}: a browser step is required — drive it via the browser-drive "
                    f"capability ({BROWSER_CONTRACT}); this deterministic player handles HTTP rungs only")
            # A wired backend would drive the rung here; the stdlib player never hard-codes one.
            raise BrowserStepRequired(f"step {i}: no browser backend wired into the player")
        else:  # pragma: no cover — validate_recipe already rejects unknown actions
            raise RecipeError(f"step {i}: unknown action {action!r}")
    return vars_


def _check_expect(step: dict, resp, text: str, i: int) -> None:
    exp = step.get("expect_status")
    if exp:
        status = _resp_status(resp)
        if status is not None and status not in exp:
            raise RecipeError(f"step {i}: status {status} not in expected {exp}")
    contains = step.get("expect_contains")
    if contains and contains not in text:
        raise RecipeError(f"step {i}: response did not contain {contains!r}")


# --- persistence (update creds → notebook → auth.env → cookie-jar) -----------
def _session_of(account: dict) -> dict:
    return account.get("session") or {}


def _persist_session(eng: Path, account_id: str, snapshot: dict) -> None:
    """Write a refreshed session back into creds.json for ``account_id``, re-sync the redacted
    notebook projection, and re-materialize ``runtime/auth.env`` so the executors pick it up — the
    SAME 3-tier scheme ``accounts`` owns. Idempotent and best-effort for the notebook sync."""
    data = accounts.load_creds(eng)
    for a in data.get("accounts", []):
        if a.get("id") == account_id:
            sess = a.setdefault("session", {})
            if snapshot.get("cookie"):
                sess["cookie"] = snapshot["cookie"]
            hdrs = snapshot.get("headers") or {}
            if hdrs:
                sess.setdefault("headers", {}).update(hdrs)
            a["status"] = "active"
            a["updated_at"] = accounts._now()
            break
    accounts.save_creds(eng, data)
    try:
        accounts._sync_notebook(eng, data.get("accounts", []))
    except Exception:
        pass
    accounts.materialize(eng)


# --- default (real) HTTP client ----------------------------------------------
class _Resp:
    __slots__ = ("status", "text")

    def __init__(self, status: int, text: str):
        self.status = status
        self.text = text


class UrllibClient:
    """Minimal stdlib HTTP client with a cookie jar — the real backend behind ``refresh_*`` when no
    client is injected. A manual ``Cookie`` header seeds the CURRENT session for the liveness probe;
    server-set cookies accumulate in a ``MozillaCookieJar`` and are re-exported on ``snapshot()``."""

    def __init__(self, *, cookie_jar_path=None, timeout: int = 20):
        import http.cookiejar
        import urllib.request
        self._cj = http.cookiejar.MozillaCookieJar()
        self._jar_path = str(cookie_jar_path) if cookie_jar_path else None
        if self._jar_path and Path(self._jar_path).is_file():
            try:
                self._cj.load(self._jar_path, ignore_discard=True, ignore_expires=True)
            except Exception:
                pass
        self._opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self._cj))
        self._timeout = timeout
        self._hdrs: dict = {}
        self._manual_cookie = ""

    def set_session(self, *, cookie: str | None = None, headers: dict | None = None) -> None:
        if cookie:
            self._manual_cookie = str(cookie)
        for k, v in (headers or {}).items():
            self._hdrs[str(k)] = str(v)

    def _do(self, method: str, url: str, data=None, headers=None) -> _Resp:
        import urllib.error
        import urllib.request
        from urllib.parse import urlencode
        h = dict(self._hdrs)
        h.update(headers or {})
        if self._manual_cookie and not any(k.lower() == "cookie" for k in h):
            h["Cookie"] = self._manual_cookie
        body = None
        if data is not None:
            body = urlencode(data).encode("utf-8") if isinstance(data, dict) else str(data).encode("utf-8")
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")
        req = urllib.request.Request(url, data=body, method=method, headers=h)
        try:
            resp = self._opener.open(req, timeout=self._timeout)  # noqa: S310 — in-scope target
            return _Resp(getattr(resp, "status", getattr(resp, "code", 0)) or 0,
                         resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            text = ""
            try:
                text = e.read().decode("utf-8", "replace")
            except Exception:
                pass
            return _Resp(e.code, text)

    def get(self, url, headers=None) -> _Resp:
        return self._do("GET", url, None, headers)

    def post(self, url, data=None, headers=None) -> _Resp:
        return self._do("POST", url, data, headers)

    def snapshot(self) -> dict:
        cookie = "; ".join(f"{c.name}={c.value}" for c in self._cj)
        if not cookie and self._manual_cookie:
            cookie = self._manual_cookie
        if self._jar_path:
            try:
                Path(self._jar_path).parent.mkdir(parents=True, exist_ok=True)
                self._cj.save(self._jar_path, ignore_discard=True, ignore_expires=True)
            except Exception:
                pass
        return {"cookie": cookie, "headers": {}}


def _default_client_factory(eng: Path):
    jar = Path(eng) / COOKIE_JAR_REL
    return lambda: UrllibClient(cookie_jar_path=jar)


# --- refresh --------------------------------------------------------------
@dataclass
class RefreshResult:
    id: str
    status: str
    reason: str = ""
    cookie_set: bool = False


def refresh_identity(eng: Path, account: dict, recipe: dict, *, client_factory=None,
                     allow_browser: bool = False) -> RefreshResult:
    """Refresh ONE identity's session, gated by a liveness probe.

    1. validate the recipe; build the ``${var}`` namespace from the stored creds;
    2. LIVENESS FIRST — probe the CURRENT stored session; if live, return ``fresh`` (no replay);
    3. stale ⇒ replay the recipe's deterministic HTTP steps on a fresh client (a ``browser`` step
       with no backend ⇒ ``needs-browser``);
    4. CONFIRM — the same probe must pass against the NEW session, else ``failed``;
    5. persist the refreshed session (creds.json → notebook → auth.env → cookie-jar) ⇒ ``refreshed``.
    """
    rid = str(account.get("id", "?"))
    try:
        validate_recipe(recipe)
    except RecipeError as e:
        return RefreshResult(rid, FAILED, f"invalid recipe: {e}")

    vars_ = vars_from_account(account)
    auth_check = substitute(recipe.get("auth_check") or {}, vars_)
    factory = client_factory or _default_client_factory(eng)

    # 2 — liveness on the CURRENT session.
    try:
        probe = factory()
        sess = _session_of(account)
        probe.set_session(cookie=sess.get("cookie"), headers=sess.get("headers"))
        if liveness_check(probe, auth_check):
            return RefreshResult(rid, FRESH, "current session is still live — no refresh needed")
    except Exception as e:
        # A probe failure is not fatal — fall through to a replay (treat as stale).
        _ = e

    # 3 — stale: replay the recipe on a fresh client.
    try:
        client = factory()
    except Exception as e:
        return RefreshResult(rid, FAILED, f"could not create an HTTP client: {type(e).__name__}: {e}")
    try:
        play(recipe, dict(vars_), client, allow_browser=allow_browser)
    except BrowserStepRequired as e:
        return RefreshResult(rid, NEEDS_BROWSER,
                             f"{e} — drive that rung via the browser-drive backend ({BROWSER_CONTRACT})")
    except RecipeError as e:
        return RefreshResult(rid, FAILED, f"login replay failed: {e}")
    except Exception as e:
        return RefreshResult(rid, FAILED, f"login replay error: {type(e).__name__}: {e}")

    # 4 — confirm the NEW session is live before trusting it.
    if not liveness_check(client, auth_check):
        return RefreshResult(rid, FAILED, "replayed the login but the liveness probe still fails")

    # 5 — capture + persist.
    try:
        snapshot = client.snapshot() if hasattr(client, "snapshot") else {}
    except Exception:
        snapshot = {}
    try:
        _persist_session(eng, rid, snapshot or {})
    except Exception as e:
        return RefreshResult(rid, FAILED, f"refreshed but could not persist: {type(e).__name__}: {e}")
    return RefreshResult(rid, REFRESHED, "session refreshed into auth.env + cookie-jar",
                         cookie_set=bool((snapshot or {}).get("cookie")))


def refresh_all(eng: Path, *, client_factory=None, allow_browser: bool = False) -> list[RefreshResult]:
    """Refresh every stored identity that has a login recipe. Identities without a recipe are
    reported ``skipped`` (never silently ignored)."""
    eng = Path(eng)
    recipes = load_recipes(eng)
    results: list[RefreshResult] = []
    for acct in accounts.load_creds(eng).get("accounts", []):
        if not isinstance(acct, dict) or not acct.get("id"):
            continue
        rid = str(acct["id"])
        rec = recipes.get(rid)
        if not rec:
            results.append(RefreshResult(rid, SKIPPED, "no login recipe for this identity"))
            continue
        results.append(refresh_identity(eng, acct, rec, client_factory=client_factory,
                                        allow_browser=allow_browser))
    return results
