#!/usr/bin/env python3
"""
dangling_dns.py -- recon-stage dangling-DNS classifier that EMITS the `asset:dangling-dns` signal.

WHY THIS EXISTS (recall fix, 2026-11-02):
  The subdomain-takeover executor is complete, but it is a non-baseline category whose routing trigger
  is `asset:dangling-dns` — and NOTHING in recon emitted that signal. So on a signal-driven coverage plan
  the takeover class was marked `skipped` ("no dangling DNS record surfaced"), even though finding dangling
  DNS is the executor's own job. The trigger was backwards (it fires only once someone already found what
  the agent finds), so a starved executor silently skipped itself — exactly the false-negative the recall
  work targets.

  This closes the loop at RECON: host-discovery already resolves CNAME/A/NS chains with `dnsx`. This module
  classifies those resolved records deterministically, flags takeover CANDIDATES, and emits
  `asset:dangling-dns` so coverage.py routes `subdomain-takeover` instead of skipping it. The executor then
  does the authoritative HTTP-fingerprint + claimability confirmation (`subdomain-takeover/refs/
  takeover_fingerprints.md`) — this is cheap DNS-level TRIAGE whose only job is "don't skip the class".

DETECTION (DNS facts only; no HTTP fetch here — that is the executor's step):
  A record is a candidate when, per `subdomain-takeover/refs/takeover_fingerprints.md`:
   1. CNAME target matches a known takeover-prone service suffix (claim-state confirmed later by the
      executor) — a candidate even if the target resolves, because "resolves" != "claimed";
   2. CNAME/NS target does NOT resolve (NXDOMAIN/SERVFAIL) — a classic dangling pointer, any suffix;
   3. dangling NS delegation (a non-resolving NS target) — higher impact, flagged separately.
  A WILDCARD record (`*.target`) is NOT a confident candidate (infinite matches) — the refs' explicit caveat.

Pure logic (DNS results injected), stdlib only, unit-tested + wired into scripts/validate.py.
`python scripts/dangling_dns.py --selftest`.
"""
from __future__ import annotations

from typing import List

SIGNAL = "asset:dangling-dns"

# Known takeover-prone CNAME-target suffixes -> service label. Seeded from
# subdomain-takeover/refs/takeover_fingerprints.md (sync with nuclei http/takeovers + can-i-take-over-xyz).
# A CNAME to one of these is a candidate; the executor confirms the claim state over HTTP.
SERVICE_SUFFIXES = {
    "s3.amazonaws.com": "AWS S3",
    "amazonaws.com": "AWS",
    "cloudfront.net": "AWS CloudFront",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "herokudns.com": "Heroku",
    "fastly.net": "Fastly",
    "azurewebsites.net": "Azure",
    "cloudapp.azure.com": "Azure",
    "cloudapp.net": "Azure",
    "blob.core.windows.net": "Azure Blob",
    "trafficmanager.net": "Azure Traffic Manager",
    "appspot.com": "GCP App Engine",
    "googlehosted.com": "GCP",
    "web.app": "Firebase",
    "firebaseapp.com": "Firebase",
    "bitbucket.io": "Bitbucket",
    "wordpress.com": "WordPress.com",
    "ghost.io": "Ghost",
    "helpscoutdocs.com": "Help Scout",
    "cargocollective.com": "Cargo Collective",
    "webflow.com": "Webflow",
    "strikinglydns.com": "Strikingly",
    "tilda.ws": "Tilda",
    "agilecrm.com": "Agile CRM",
    "statuspage.io": "Statuspage",
    "vercel-dns.com": "Vercel",
    "surge.sh": "Surge.sh",
    "netlify.app": "Netlify",
    "netlify.com": "Netlify",
    "pantheonsite.io": "Pantheon",
    "readthedocs.io": "Read the Docs",
    "readme.io": "ReadMe",
    "zendesk.com": "Zendesk",
    "myshopify.com": "Shopify",
    "unbouncepages.com": "Unbounce",
    "tumblr.com": "Tumblr",
}


def match_service(target: str):
    """Longest-suffix match of a CNAME/NS target against the known takeover-prone services."""
    t = (target or "").strip().rstrip(".").lower()
    best = None
    for suf, name in SERVICE_SUFFIXES.items():
        if t == suf or t.endswith("." + suf):
            if best is None or len(suf) > len(best[0]):
                best = (suf, name)
    return best[1] if best else None


def classify(records) -> dict:
    """Classify resolved DNS records into takeover candidates + the emit decision (pure logic).

    records: [{subdomain, record_type ('CNAME'|'NS'|'A'|'AAAA'), target,
               target_resolves (bool), is_wildcard (bool, default False)}, ...]
    Returns {candidates:[{subdomain,record_type,target,service,reason,confidence}],
             skipped_wildcards:[subdomain], signals:[...], emit: bool}.
    """
    candidates, wildcards = [], []
    for r in records or []:
        sub = r.get("subdomain")
        rtype = (r.get("record_type") or "").upper()
        target = r.get("target") or ""
        resolves = bool(r.get("target_resolves", True))
        if r.get("is_wildcard"):
            wildcards.append(sub)
            continue  # explicit-record caveat: a wildcard CNAME is not a confident candidate
        if rtype == "CNAME":
            service = match_service(target)
            if service and not resolves:
                candidates.append({"subdomain": sub, "record_type": rtype, "target": target,
                                   "service": service, "reason": "known-service CNAME, target NXDOMAIN",
                                   "confidence": "high"})
            elif service:
                candidates.append({"subdomain": sub, "record_type": rtype, "target": target,
                                   "service": service, "reason": "known takeover-prone service CNAME",
                                   "confidence": "medium"})
            elif not resolves:
                candidates.append({"subdomain": sub, "record_type": rtype, "target": target,
                                   "service": None, "reason": "dangling CNAME, target does not resolve",
                                   "confidence": "medium"})
        elif rtype == "NS" and not resolves:
            candidates.append({"subdomain": sub, "record_type": rtype, "target": target,
                               "service": match_service(target), "reason": "dangling NS delegation",
                               "confidence": "high"})
        # A/AAAA dangling needs passive-DNS history to call — out of deterministic DNS-only scope here.
    emit = bool(candidates)
    return {"candidates": candidates, "skipped_wildcards": wildcards,
            "signals": [SIGNAL] if emit else [], "emit": emit}


def selftest() -> None:
    # suffix matching (longest wins; sub-of-service matches)
    assert match_service("myapp.herokuapp.com") == "Heroku"
    assert match_service("foo.bar.github.io") == "GitHub Pages"
    assert match_service("bucket.s3.amazonaws.com") == "AWS S3"          # longer suffix beats "amazonaws.com"
    assert match_service("legit.example.com") is None

    recs = [
        # 1. known service, target resolves -> candidate (medium; executor confirms claim state over HTTP)
        {"subdomain": "docs.t.com", "record_type": "CNAME", "target": "t.github.io", "target_resolves": True},
        # 2. known service, NXDOMAIN -> high
        {"subdomain": "cdn.t.com", "record_type": "CNAME", "target": "old.herokuapp.com", "target_resolves": False},
        # 3. dangling CNAME to unknown target -> medium
        {"subdomain": "legacy.t.com", "record_type": "CNAME", "target": "gone.vendor.net", "target_resolves": False},
        # 4. dangling NS -> high
        {"subdomain": "zone.t.com", "record_type": "NS", "target": "ns1.deprovisioned.net", "target_resolves": False},
        # 5. wildcard -> skipped (not a confident candidate)
        {"subdomain": "*.t.com", "record_type": "CNAME", "target": "x.github.io", "target_resolves": True,
         "is_wildcard": True},
        # 6. in-house CNAME that resolves, no known service -> NOT a candidate
        {"subdomain": "app.t.com", "record_type": "CNAME", "target": "lb.t.com", "target_resolves": True},
        # 7. plain A record -> not classified here
        {"subdomain": "mail.t.com", "record_type": "A", "target": "203.0.113.5", "target_resolves": True},
    ]
    res = classify(recs)
    subs = {c["subdomain"]: c for c in res["candidates"]}
    assert set(subs) == {"docs.t.com", "cdn.t.com", "legacy.t.com", "zone.t.com"}, subs
    assert subs["docs.t.com"]["confidence"] == "medium" and subs["docs.t.com"]["service"] == "GitHub Pages"
    assert subs["cdn.t.com"]["confidence"] == "high"
    assert subs["zone.t.com"]["record_type"] == "NS" and subs["zone.t.com"]["confidence"] == "high"
    assert res["skipped_wildcards"] == ["*.t.com"]
    assert res["emit"] is True and res["signals"] == [SIGNAL]

    # no takeover surface at all -> no signal emitted (so the class legitimately skips with a real reason)
    clean = classify([
        {"subdomain": "app.t.com", "record_type": "CNAME", "target": "lb.t.com", "target_resolves": True},
        {"subdomain": "t.com", "record_type": "A", "target": "203.0.113.1", "target_resolves": True},
    ])
    assert clean["emit"] is False and clean["signals"] == [] and clean["candidates"] == []

    print("dangling_dns selftest: OK")


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        selftest()
    else:
        print(__doc__)
