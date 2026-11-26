"""Parse a browser 'Copy as cURL' string into the fields ``accounts.build_account()`` expects.

Chrome/Firefox/Edge devtools 'Copy as cURL' emits a shell ``curl`` invocation carrying a request's
URL, its headers (including the session ``Cookie`` and any ``Authorization`` bearer) and body. An
operator who already holds an authenticated browser session can PASTE that one string instead of
hand-transcribing the cookie/token into ``creds.json`` — this replaces the ad-hoc hand-written
loader. This module turns that paste into the structured session material the accounts store already
knows how to persist (``creds.json``) + materialize (``runtime/auth.env``).

Stdlib only (``re`` · ``shlex`` · ``urllib.parse``). PURE: no filesystem, no network, no
intra-package import — the caller (``redstrike session import``) maps the parsed fields onto
``accounts.build_account()`` and attaches ``base_url``. Both the bash form (single quotes,
``\\``-continuations, ``$'...'`` ANSI-C quoting) and the Windows cmd form (double quotes,
``^``-continuations) are tolerated.

``parse_curl`` is faithful — it keeps EVERY header. ``ParsedCurl.account_fields()`` is the
store-this projection: it drops the per-request browser-noise headers (``user-agent``,
``accept*``, ``sec-*``, …) and keeps the session-identity material (cookie, bearer, custom
``x-*``/auth headers), so the imported ``auth.env`` is the session, not browser chrome.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from urllib.parse import urlsplit

# curl flags that CONSUME the following token (anything else starting with '-' is treated boolean).
_ARG_FLAGS = frozenset({
    "-H", "--header",
    "-b", "--cookie",
    "-X", "--request",
    "-d", "--data", "--data-raw", "--data-binary", "--data-ascii", "--data-urlencode",
    "-u", "--user",
    "--url",
    "-e", "--referer",
    "-A", "--user-agent",
    "-o", "--output",
    "-m", "--max-time", "--connect-timeout",
})
_DATA_FLAGS = frozenset({"-d", "--data", "--data-raw", "--data-binary", "--data-ascii",
                         "--data-urlencode"})

# Per-request browser chrome — NOT session identity. Dropped by account_fields() so a pasted
# request does not pollute the stored session with 15 noise headers (a custom x-* / auth header,
# the Cookie and the Authorization bearer are all kept — those ARE the session).
_NOISE_HEADERS = frozenset({
    "accept", "accept-encoding", "accept-language", "accept-charset",
    "user-agent", "upgrade-insecure-requests", "pragma", "cache-control", "dnt", "priority",
    "referer", "origin", "connection", "te", "host", "content-length", "content-type",
    "if-none-match", "if-modified-since",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-ch-ua-platform-version",
    "sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-model", "sec-ch-ua-wow64",
    "sec-ch-ua-full-version", "sec-ch-ua-full-version-list",
    "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
})


@dataclass
class ParsedCurl:
    url: str = ""
    base_url: str = ""                             # scheme://netloc — attached to the account
    method: str = ""
    headers: dict = field(default_factory=dict)    # ALL non-cookie, non-bearer headers (name->value)
    cookie: str = ""                               # from -b/--cookie or a `Cookie:` header
    token: str = ""                                # bearer token from `Authorization: Bearer <t>`
    data: str = ""
    basic_user: str = ""                           # from -u user:pass
    basic_pass: str = ""

    def account_fields(self) -> dict:
        """The subset of ``accounts.build_account()`` kwargs this cURL fills (only non-empty),
        PLUS ``base_url`` (which the caller attaches after ``build_account()``). Browser-noise
        headers are dropped; the cookie, bearer and any custom/auth headers are kept."""
        out: dict = {}
        if self.cookie:
            out["cookie"] = self.cookie
        if self.token:
            out["token"] = self.token
        hdrs = {k: v for k, v in self.headers.items() if k.lower() not in _NOISE_HEADERS}
        if hdrs:
            out["headers"] = hdrs
        if self.basic_user:
            out["identity"] = self.basic_user
        if self.basic_pass:
            out["password"] = self.basic_pass
        if self.base_url:
            out["base_url"] = self.base_url
        return out


def _preprocess(s: str) -> str:
    s = (s or "").strip()
    # ANSI-C quoting ($'...') → plain quoting (we only need the literal value, not the escapes).
    s = s.replace("$'", "'").replace('$"', '"')
    # Join line continuations: a trailing '\' (bash), '^' (cmd) or '`' (pwsh) before a newline.
    s = re.sub(r"[\\^`]\r?\n", " ", s)
    s = re.sub(r"\r?\n", " ", s)
    return s.strip()


def _split(s: str) -> list:
    try:
        return shlex.split(s, posix=True)
    except ValueError:
        # Unbalanced quote (a stray quote inside a value) — degrade to a lenient split rather than raise.
        return [t for t in re.split(r"\s+", s) if t]


def _merge_cookie(existing: str, new: str) -> str:
    new = (new or "").strip().rstrip(";").strip()
    if not new:
        return existing
    if not existing:
        return new
    return existing.rstrip(";").strip() + "; " + new


def _looks_like_url(tok: str) -> bool:
    # A browser 'Copy as cURL' always emits a full-scheme URL, so a bare argument is only treated as
    # the URL when it carries a scheme — this keeps stray words (a mangled paste) from becoming one.
    return "://" in (tok or "")


def _set_url(pc: ParsedCurl, url: str) -> None:
    url = (url or "").strip()
    if not url:
        return
    pc.url = url
    parts = urlsplit(url)
    if parts.scheme and parts.netloc:
        pc.base_url = f"{parts.scheme}://{parts.netloc}"


def _add_header(pc: ParsedCurl, raw: str) -> None:
    name, sep, value = (raw or "").partition(":")
    if not sep:
        return
    name = name.strip()
    value = value.strip()
    if not name:
        return
    low = name.lower()
    if low == "cookie":
        pc.cookie = _merge_cookie(pc.cookie, value)
        return
    if low == "authorization":
        m = re.match(r"(?i)\s*bearer\s+(.+)$", value)
        if m:
            pc.token = m.group(1).strip()
            return
        # Non-bearer auth (Basic/Digest/custom) — keep it as a header.
    pc.headers[name] = value


def parse_curl(s: str) -> ParsedCurl:
    """Parse a 'Copy as cURL' string into a :class:`ParsedCurl`. Never raises on malformed input —
    an empty/garbage string yields an empty ParsedCurl (``.url == ""``), which the caller rejects."""
    tokens = _split(_preprocess(s))
    pc = ParsedCurl()
    i, n = 0, len(tokens)
    if tokens and tokens[0].lower() == "curl":
        i = 1
    while i < n:
        tok = tokens[i]
        if tok.startswith("--") and "=" in tok:          # --flag=value form
            flag, val = tok.split("=", 1)
        elif tok in _ARG_FLAGS:                           # flag consumes the next token
            flag = tok
            val = tokens[i + 1] if i + 1 < n else ""
            i += 1
        else:
            flag, val = tok, None
        low = flag.lower()
        if low in ("-h", "--header"):
            _add_header(pc, val or "")
        elif low in ("-b", "--cookie"):
            if val and "=" in val:                        # a cookie string, not an @cookiejar file
                pc.cookie = _merge_cookie(pc.cookie, val)
        elif low in ("-x", "--request"):
            pc.method = (val or "").upper()
        elif low in ("-u", "--user"):
            user, _, pw = (val or "").partition(":")
            pc.basic_user, pc.basic_pass = user, pw
        elif low == "--url":
            _set_url(pc, val or "")
        elif flag in _DATA_FLAGS:
            pc.data = (pc.data + "&" + (val or "")) if pc.data else (val or "")
            if not pc.method:
                pc.method = "POST"
        elif flag.startswith("-"):
            pass                                          # boolean flag (compressed/silent/location/…)
        elif not pc.url and _looks_like_url(flag):
            _set_url(pc, flag)                            # the first bare scheme'd token is the URL
        i += 1
    if not pc.method:
        pc.method = "GET"
    return pc
