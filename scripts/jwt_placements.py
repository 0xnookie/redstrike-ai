#!/usr/bin/env python3
"""
jwt_placements.py -- deterministic forged-JWT carrier enumeration for the JWT executor.

WHY THIS EXISTS (recall fix, 2026-11-02):
  To CONFIRM a JWT flaw you must get the server to ACCEPT the forged / tampered token. The
  silent failure mode is to send the forged token ONLY in the `Authorization: Bearer`
  header, get a 401, and conclude "not vulnerable" -- when the app actually reads the token
  from a COOKIE and would have accepted it there.

  Live proof: OWASP Juice Shop v20.3.0. A forged `alg:none` token in `Authorization: Bearer`
  did NOT trip the Unsigned-JWT challenge; the SAME token placed in the `token` COOKIE did.
  Juice Shop's middleware reads the token from `req.cookies.token` as well as the header. A
  header-only send is a false negative for every cookie-reading app -- and cookie carriage is
  often invisible to recon, so you cannot rely on having "observed" it first.

THE RULE THIS ENCODES:
  1. A forged token is sent in BOTH a header carrier AND a cookie carrier -- always. The
     mandatory core is `Authorization: Bearer` + the `token` cookie. Header-only is never a
     complete test, regardless of what recon observed.
  2. Add every carrier recon actually OBSERVED the valid token travel in (exact names), plus
     the common defaults, deduped.
  3. "Forged token NOT accepted" is only a valid (clean) verdict when the token was sent in
     at least the full mandatory set and none granted access. If any mandatory carrier was
     skipped, that is an OPEN-PROOF-GAP (see _contract/counterevidence.md), never "ruled out".

This module is PURE LOGIC (stdlib only): it enumerates carriers and renders how to attach a
token; the executor wires the carriers to its interceptor / curl and scope-rate ladder. That
keeps it deterministic and unit-testable with no network (the CI convention).

`python scripts/jwt_placements.py --selftest` runs the self-test.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple


@dataclass(frozen=True)
class Placement:
    """One carrier a token can ride in."""

    kind: str  # "header" | "cookie"
    name: str  # header or cookie name (exact case preserved for rendering)
    scheme: str = ""  # header auth scheme, e.g. "Bearer"; "" for a bare value / a cookie
    source: str = "default"  # "mandatory" | "observed" | "default"

    def key(self) -> Tuple[str, str]:
        # Dedup identity: kind + case-folded name. HTTP header names are case-insensitive;
        # cookie names are technically case-sensitive (RFC 6265) but frameworks routinely
        # read them loosely, so folding case avoids sending a near-duplicate carrier. The
        # first-added spelling (mandatory/observed) is the one kept and sent.
        return (self.kind, self.name.lower())

    def render(self, token: str) -> Tuple[str, str]:
        """Return (carrier_kind, wire_line) describing how to attach `token`.

        header -> ("header", "Authorization: Bearer <token>")
        cookie -> ("cookie", "token=<token>")
        """
        if self.kind == "header":
            value = f"{self.scheme} {token}".strip() if self.scheme else token
            return ("header", f"{self.name}: {value}")
        if self.kind == "cookie":
            return ("cookie", f"{self.name}={token}")
        raise ValueError(f"unknown carrier kind: {self.kind!r}")


# The two carriers every forged-token confirmation MUST include: one header, one cookie.
# `Authorization: Bearer` is the near-universal header carrier; `token` is the cookie that
# Juice Shop (express-jwt + cookie middleware) reads -- the live case this fix exists for.
MANDATORY: Tuple[Placement, ...] = (
    Placement("header", "Authorization", scheme="Bearer", source="mandatory"),
    Placement("cookie", "token", source="mandatory"),
)

# Belt-and-suspenders defaults, appended AFTER the mandatory core + observed carriers.
_DEFAULT_HEADERS: Tuple[str, ...] = ("X-Access-Token", "X-Auth-Token", "X-JWT")
_DEFAULT_COOKIES: Tuple[str, ...] = (
    "jwt",
    "access_token",
    "accessToken",
    "auth",
    "authorization",
    "id_token",
    "session",
)


def enumerate_placements(
    observed: Optional[Iterable[Placement]] = None,
    include_defaults: bool = True,
) -> List[Placement]:
    """Return the deduped, ordered carrier list to send a forged JWT in.

    Order: mandatory core (header + cookie) -> observed carriers -> common defaults.
    `observed` are carriers recon actually saw the valid token travel in (exact names); an
    observed carrier that collapses onto a mandatory one keeps the mandatory spelling.
    """
    out: List[Placement] = []
    seen: set = set()

    def add(p: Placement) -> None:
        if p.key() not in seen:
            seen.add(p.key())
            out.append(p)

    for p in MANDATORY:
        add(p)
    for p in observed or []:
        add(p)
    if include_defaults:
        for hname in _DEFAULT_HEADERS:
            add(Placement("header", hname, source="default"))
        for cname in _DEFAULT_COOKIES:
            add(Placement("cookie", cname, source="default"))
    return out


def missing_mandatory(sent: Iterable[Placement]) -> List[Placement]:
    """Return the mandatory carriers NOT present in `sent` (by carrier identity)."""
    sent_keys = {p.key() for p in sent}
    return [p for p in MANDATORY if p.key() not in sent_keys]


def confirmation_complete(sent: Iterable[Placement]) -> bool:
    """True iff the forged token was sent in at least the full mandatory set.

    A 'forged token NOT accepted' verdict is only valid (clean) when this is True. Otherwise
    the result is an open-proof-gap, not a ruled-out finding -- the header-only false negative
    this helper exists to prevent.
    """
    return not missing_mandatory(sent)


def spans_header_and_cookie(sent: Iterable[Placement]) -> bool:
    """True iff `sent` includes at least one header carrier AND one cookie carrier."""
    kinds = {p.kind for p in sent}
    return "header" in kinds and "cookie" in kinds


# --------------------------------------------------------------------------------------
# Self-test (no network; pure logic). Wired into scripts/validate.py like the other helpers.
# --------------------------------------------------------------------------------------
def selftest() -> None:
    # 1) The enumeration ALWAYS leads with a header + cookie mandatory core.
    places = enumerate_placements()
    assert places[0].kind == "header" and places[0].name == "Authorization"
    assert places[0].scheme == "Bearer"
    assert spans_header_and_cookie(places), "enumeration must span header AND cookie"

    # 2) REGRESSION (Juice Shop v20.3.0): the `token` cookie is mandatory -- a header-only
    #    confirmation misses it. This is the exact live false negative.
    assert any(p.kind == "cookie" and p.name == "token" for p in MANDATORY)
    header_only = [MANDATORY[0]]
    assert confirmation_complete(header_only) is False, (
        "header-only send must NOT count as a complete confirmation"
    )
    miss = missing_mandatory(header_only)
    assert len(miss) == 1 and miss[0].kind == "cookie" and miss[0].name == "token"

    # 3) Header + `token` cookie together => complete.
    assert confirmation_complete(list(MANDATORY)) is True
    assert confirmation_complete(enumerate_placements()) is True

    # 4) Cookie-only is ALSO incomplete (the symmetric gap: a header-reading app).
    cookie_only = [MANDATORY[1]]
    assert confirmation_complete(cookie_only) is False
    assert missing_mandatory(cookie_only)[0].kind == "header"

    # 5) Dedup: an observed carrier that collapses onto a mandatory one does not duplicate it,
    #    and case differences fold (HTTP header names are case-insensitive).
    observed = [
        Placement("header", "authorization", scheme="Bearer", source="observed"),  # dup of mandatory
        Placement("cookie", "token", source="observed"),  # dup of mandatory
        Placement("cookie", "sessionJwt", source="observed"),  # genuinely new
    ]
    enr = enumerate_placements(observed=observed, include_defaults=False)
    keys = [p.key() for p in enr]
    assert len(keys) == len(set(keys)), "no duplicate carriers"
    assert ("cookie", "sessionjwt") in keys, "a genuinely new observed carrier is included"
    # The kept Authorization spelling is the mandatory one (added first), not the observed lower-case.
    auth = [p for p in enr if p.key() == ("header", "authorization")][0]
    assert auth.name == "Authorization" and auth.source == "mandatory"

    # 6) include_defaults widens the net with common carriers, still deduped + still complete.
    wide = enumerate_placements()
    wkeys = [p.key() for p in wide]
    assert len(wkeys) == len(set(wkeys))
    assert ("cookie", "jwt") in wkeys and ("header", "x-access-token") in wkeys
    assert confirmation_complete(wide) is True

    # 7) render() formats a Bearer header and a cookie correctly.
    assert MANDATORY[0].render("T") == ("header", "Authorization: Bearer T")
    assert MANDATORY[1].render("T") == ("cookie", "token=T")
    assert Placement("header", "X-JWT").render("T") == ("header", "X-JWT: T")

    print("jwt_placements selftest: OK")


if __name__ == "__main__":
    import sys

    if "--selftest" in sys.argv:
        selftest()
    else:
        print(__doc__)
