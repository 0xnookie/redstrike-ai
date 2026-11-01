#!/usr/bin/env python3
"""
escalation.py -- the empty-class escalation ladder (recall fix #3).

WHY THIS EXISTS:
  "empty == clear" is the quiet recall killer. When an executor returns 0 findings on a surface
  the recon signals say is a real candidate (a high-prior surface), a bare "attempted, nothing
  found" is indistinguishable from an EXHAUSTIVE clear -- but usually it just means the first
  payload shape didn't land. counterevidence.md states the principle ("missing information is not
  proof of safety"); this module makes it OPERATIONAL and deterministic: before a high-prior
  surface may be called clean, the class's escalation LADDER must be exhausted (or a blocker
  recorded as an open-proof-gap).

  The ladders are grounded in escalations that actually unblocked findings in the juice-shop
  recall run:
    - SQLi: DERIVE the UNION column count (scripts/sqli_union.py), don't assume 9 -> it was 10.
    - XSS:  render in a REAL browser (client-side detection) -> DOM/Reflected only tripped there.
    - JWT:  send the forged token in the `token` COOKIE, not only the Authorization header.

This is PURE LOGIC + data (no network); the executor injects what it observed (findings count,
the surface's prior, blockers seen, techniques already tried) and gets a deterministic verdict +
the ordered techniques still to try. Stdlib only. `python scripts/escalation.py --selftest`.
"""
from __future__ import annotations

from typing import Iterable

# Ordered escalation techniques per class FAMILY. Try top-to-bottom before declaring a high-prior
# surface clean. Technique ids are stable tokens an executor records as it tries them.
_LADDERS = {
    "sqli": [
        "derive-not-assume",        # UNION column count via sqli_union (never hard-code) — the 10-col lesson
        "encoding-ladder",          # url / double-url / unicode / hex
        "waf-bypass",               # case toggle, inline comments, whitespace alts
        "alt-content-type",         # json / xml / form-encoded body variants
        "header-injection",         # UA / Referer / X-Forwarded-* / Cookie sinks
        "second-order",             # store benign, trigger on a later read
        "oob-channel",              # collaborator canary (if one is in scope)
    ],
    "xss": [
        "browser-render",           # execute in a REAL browser — client-side detection (DOM/reflected lesson)
        "api-inject-bypass-client", # post via API to dodge the client-side sanitizer
        "context-variants",         # attribute / js-string / url / template contexts
        "header-xss",               # stored header reflected unsanitized
        "stored-cross-user",        # store as A, render as B
        "csp-aware-payload",        # payload that survives/uses the page's CSP
    ],
    "authz": [
        "second-identity",          # >=2 accounts (A accesses B's object)
        "sibling-ids",              # enumerate adjacent object ids
        "verb-swap",                # GET vs POST vs PUT vs DELETE on the same route
        "mass-assignment",          # extra privileged fields in the body
        "nested-ref",               # nested / aliased object refs (GraphQL node ids)
    ],
    "auth": [
        "token-cookie-and-header",  # forged token in BOTH the cookie AND Authorization (the JWT lesson)
        "alg-confusion",            # alg:none / RS256->HS256 key confusion
        "reset-and-recovery",       # security-question / weak reset / change-without-current
        "policy-safe-spray",        # known defaults, lockout-safe
        "token-tamper-replay",      # claim tamper + replay
    ],
    "exposure": [
        "custom-wordlist",          # target-specific content-discovery wordlist
        "filter-bypass",            # null-byte / double-encode / case on the path filter
        "backup-vcs-temp",          # .bak / ~ / .git / .swp / .DS_Store extensions
        "auth-vs-unauth-diff",      # diff authenticated vs anonymous surface
    ],
    "generic": [
        "retrigger-different-path", # re-observe via an independent request/command
        "match-blocker",            # escalate to the technique matching the observed blocker
        "widen-input-space",        # once: broaden encoding / payload shape
    ],
}

# class id -> family (explicit where a keyword would be ambiguous; else keyword-matched below).
_CLASS_FAMILY = {
    "sqli": "sqli", "sqli-inband": "sqli", "sqli-blind": "sqli", "nosql-injection": "sqli",
    "ldap-injection": "sqli", "injection": "sqli", "command-injection": "sqli", "ssti": "sqli",
    "deserialization": "sqli", "xxe": "sqli", "xxe-inband": "sqli", "xxe-blind": "sqli",
    "prototype-pollution": "sqli",
    "xss": "xss", "xss-reflected": "xss", "xss-stored": "xss", "xss-dom": "xss", "xss-blind": "xss",
    "authz": "authz", "idor": "authz", "privesc": "authz", "api": "authz", "bola-bfla": "authz",
    "graphql": "authz", "parameter-pollution": "authz",
    "auth": "auth", "jwt": "auth", "oauth": "auth", "crypto-attacks": "auth",
    "exposed-surface": "exposure", "secrets": "exposure", "file": "exposure",
    "path-traversal-lfi": "exposure", "upload-rce": "exposure",
}

# observed-blocker -> the technique id it should promote to the FRONT of the ladder.
_BLOCKER_PROMOTES = {
    "waf": "waf-bypass", "403": "waf-bypass", "406": "waf-bypass",
    "client-sanitizer": "api-inject-bypass-client",
    "no-js-execution": "browser-render",
    "single-identity": "second-identity",
    "header-only-token": "token-cookie-and-header",
    "assumed-column-count": "derive-not-assume",
    "path-filter": "filter-bypass",
}


def family_for(class_id: str) -> str:
    cid = (class_id or "").lower()
    if cid in _CLASS_FAMILY:
        return _CLASS_FAMILY[cid]
    for key, fam in _CLASS_FAMILY.items():
        if key in cid:
            return fam
    for fam in ("sqli", "xss", "authz", "auth", "exposure"):
        if fam in cid:
            return fam
    return "generic"


def ladder_for(class_id: str, blockers: Iterable[str] = ()) -> list:
    """The ordered escalation ladder for a class, with any technique matching an observed
    blocker promoted to the front (fix the specific block first, don't burn the whole ladder)."""
    fam = family_for(class_id)
    base = list(_LADDERS[fam])
    promoted = []
    for b in blockers or ():
        t = _BLOCKER_PROMOTES.get(str(b).lower())
        if t and t in base and t not in promoted:
            promoted.append(t)
    rest = [t for t in base if t not in promoted]
    return promoted + rest


def assess(class_id: str, findings_count: int, prior: str = "unknown",
           escalations_done: Iterable[str] = (), blockers: Iterable[str] = ()) -> dict:
    """Decide whether a result may be called clean, or must escalate first.

    prior: "high" (recon flagged this surface a real candidate), "low" (no signal), or "unknown".
    Returns {verdict, remaining, ladder}. Verdicts:
      - "found"                 findings_count > 0 — nothing to escalate.
      - "clear-ok"              low-prior empty — an acceptable clear.
      - "clear-after-escalation" high/unknown-prior empty AND the ladder is exhausted — honest clear.
      - "escalate"              high/unknown-prior empty with ladder steps left — a SHALLOW clear,
                                NOT trustworthy; `remaining` lists what to try next.
    unknown prior is treated conservatively like high (recall-safe default — matches the coverage
    'attempt all with no signals' policy): an untested-prior empty must try the ladder once."""
    ladder = ladder_for(class_id, blockers)
    if findings_count and findings_count > 0:
        return {"verdict": "found", "remaining": [], "ladder": ladder}
    if prior == "low":
        return {"verdict": "clear-ok", "remaining": [], "ladder": ladder}
    done = set(escalations_done or ())
    remaining = [t for t in ladder if t not in done]
    if not remaining:
        return {"verdict": "clear-after-escalation", "remaining": [], "ladder": ladder}
    return {"verdict": "escalate", "remaining": remaining, "ladder": ladder}


def needs_escalation(class_id: str, findings_count: int, prior: str = "unknown",
                     escalations_done: Iterable[str] = (), blockers: Iterable[str] = ()) -> bool:
    return assess(class_id, findings_count, prior, escalations_done, blockers)["verdict"] == "escalate"


def selftest() -> None:
    # 1) A find short-circuits — no escalation when something was already found.
    assert assess("sqli", 1, "high")["verdict"] == "found"

    # 2) High-prior empty must escalate, and the SQLi ladder leads with derive-not-assume
    #    (the 10-column lesson) — a capped UNION guess is NOT a clean result.
    a = assess("sqli", 0, "high")
    assert a["verdict"] == "escalate"
    assert a["remaining"][0] == "derive-not-assume"

    # 3) Low-prior empty is an acceptable clear (don't burn effort on no-signal surfaces).
    assert assess("open-redirect", 0, "low")["verdict"] == "clear-ok"

    # 4) Unknown prior is conservative (recall-safe): still escalate.
    assert assess("sqli", 0, "unknown")["verdict"] == "escalate"

    # 5) Exhausted ladder -> honest clear-after-escalation.
    full = _LADDERS[family_for("sqli")]
    assert assess("sqli", 0, "high", escalations_done=full)["verdict"] == "clear-after-escalation"

    # 6) XSS high-prior empty leads with browser-render (client-side detection lesson).
    assert assess("xss-dom", 0, "high")["remaining"][0] == "browser-render"
    # ...and a client-sanitizer blocker promotes the API-bypass technique to the front.
    assert assess("xss", 0, "high", blockers=["client-sanitizer"])["remaining"][0] == "api-inject-bypass-client"

    # 7) JWT/auth high-prior empty leads with the cookie+header token lesson.
    assert assess("jwt", 0, "high")["remaining"][0] == "token-cookie-and-header"

    # 8) A WAF blocker promotes waf-bypass to the front of the SQLi ladder.
    assert assess("sqli", 0, "high", blockers=["waf"])["remaining"][0] == "waf-bypass"

    # 9) Family resolution incl. keyword fallback + generic default.
    assert family_for("sqli-blind") == "sqli"
    assert family_for("something-xss-weird") == "xss"
    assert family_for("brand-new-class") == "generic"

    print("escalation selftest: OK")


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        selftest()
    else:
        print(__doc__)
