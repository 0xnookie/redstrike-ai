# OAuth / OIDC black-box response oracles
# Authorized, in-scope flow only. Use TEST accounts; route any TEST code/token to YOUR OOB host only —
# never capture a real user's code. Probes here are DIAGNOSTIC: they read the provider's error wording to
# decide WHICH attack from `auth-context/refs/auth_techniques.md` is live, before you spend a real flow on it.

## Why oracles first
The token endpoint and the callback page answer black-box questions *before* you run a full flow. Two
one-shot requests tell you whether the client is public (no secret) and whether PKCE is enforced — the two
preconditions that turn a stolen `code` into account takeover. Read the oracle, THEN escalate to the matching
`auth_techniques.md` technique. A fake/expired `code` is enough; you never need a victim's artifact to read
these oracles.

## 1. Public vs confidential client (secret-requirement oracle)
POST the token endpoint with a bogus `code` and **no `client_secret`**. The error *class* leaks the client type:

```bash
# No client_secret, fake code:
curl -s -X POST "https://auth.TARGET/oauth/token" \
  -d "grant_type=authorization_code&code=fake&client_id=CLIENT_ID&redirect_uri=REDIRECT"
```

| Response error | Meaning | Action |
|---|---|---|
| `invalid_grant` | secret was NOT required — **public client** | ESCALATE: a leaked `code` is directly redeemable |
| `invalid_client` | secret IS required — **confidential client** | code alone is not enough; pivot to secret recovery / PKCE |

`invalid_grant` means the server got *past* client authentication and only the code was rejected → no secret
gate. That is the single most load-bearing OAuth oracle: a public client collapses "steal a code" straight
into ATO.

## 2. PKCE enforcement oracle
POST the token endpoint with a bogus `code` and **no `code_verifier`**. Distinguish "code is just invalid"
from "verifier is required":

```bash
# No code_verifier:
curl -s -X POST "https://auth.TARGET/oauth/token" \
  -d "grant_type=authorization_code&code=fake&client_id=CLIENT_ID&redirect_uri=REDIRECT"
```

| Response | Meaning | Action |
|---|---|---|
| `invalid_grant` (code rejected, verifier never mentioned) | **PKCE NOT enforced** at redemption | ESCALATE: a stolen auth code is usable with no verifier |
| `invalid_request` / `code_verifier required` / `PKCE ... required` | **PKCE enforced** | the code is bound to a challenge; chain only via downgrade (see below) |

If PKCE is enforced, the downgrade path is: request `/authorize` **without** `code_challenge`, then redeem
**without** `code_verifier` (TEST account only — see the PKCE-downgrade proof in
`auth-context/refs/auth_techniques.md`). The oracle tells you whether that downgrade is even worth a flow.

## 3. Auth-code leakage to analytics / third-party SDKs
The callback URL carries the live `?code=` in the location bar. If an analytics or session-replay SDK fires a
page-view with the **full URL**, the code is shipped to a third party *before* the app exchanges it — a leak
with no redirect_uri bug required.

```bash
# (a) Does the callback page load an analytics / replay SDK? (benign TEST code)
curl -s "https://TARGET/callback?code=test_probe&state=test" | \
  grep -oiE 'gtag|googletagmanager|G-[A-Z0-9]{6,}|ga4|analytics\.js|logrocket|lrkt|segment|cdn\.segment|mixpanel|amplitude|heap|hotjar|fullstory|datadog-rum' | sort -u
```

- A hit means the callback page is instrumented. The SDK's default `page_view` / page-load beacon sends
  `document.location.href` — which still contains the `code` — to the vendor collector.
- **Confirm acceptance benignly** by replaying the beacon shape with YOUR TEST code only and checking the
  collector accepts it (a `204 No Content` is the GA4 "event accepted" signal):

```bash
# Confirm the collector 204s on a page_view carrying the TEST callback URL (TEST code, your own):
curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  "https://region1.google-analytics.com/g/collect?v=2&tid=G-XXXXXXX" \
  --data-urlencode "en=page_view" \
  --data-urlencode "dl=https://TARGET/callback?code=test_probe"
# 204 => the beacon is accepted; a real callback's code would be exfiltrated the same way.
```

- Severity hinges on the recipient: a first-party-only collector is lower impact than a shared SaaS replay
  tool (LogRocket / FullStory) where support staff or a breached vendor can read the recorded URL. Evidence =
  the SDK tag on the callback page + the collector accepting the beacon. Pair with Oracle 1/2: **leaked code +
  public client + no PKCE = ATO** (see chain below). Keep to YOUR TEST session; never record a real user's URL.

## 4. Full OAuth black-box audit checklist (run in order)
Each rung reads an oracle; a PASS (escalate) feeds the next. Stop and hand off to the matching
`auth_techniques.md` technique the moment a rung escalates.

1. **Public-client oracle** (§1) — token endpoint, no secret → `invalid_grant` = public → escalate.
2. **PKCE oracle** (§2) — token endpoint, no verifier → `invalid_grant` = not enforced → escalate.
3. **`state` presence** — is `state` in the `/authorize` URL and checked on return? Missing/replayable →
   login CSRF / forced linking (→ `auth_techniques.md` state/nonce/PKCE matrix).
4. **Analytics leak** (§3) — SDK on the callback page + collector 204 → code exfil to a third party.
5. **`redirect_uri` variants** — probe the allowlist matrix (suffix / subdomain / path-traversal / `@` / HPP /
   encoded `#`): `https://TARGET/cb@TOKEN.oob.example`, `https://TARGET.evil.com/cb`,
   `https://TARGET/cb/../evil`, `https://TARGET/cb%23@evil`, `redirect_uri` sent twice (→ full matrix in
   `auth_techniques.md`).
6. **ATO chain** — assemble: a code-leak channel (§3 analytics, or a redirect_uri/Referer/fragment leak) +
   public client (§1) + no PKCE (§2) → a leaked TEST code redeems to a TEST token → read a TEST-only resource
   to prove takeover, then stop. All with accounts you own; code/token to YOUR OOB host only; approval-gated.

## Hand-back
Record each oracle result (`public_client`, `pkce_enforced`, `analytics_on_callback`, `state_checked`,
`redirect_uri_variant_passed`) with the exact provider error string as evidence, and route the first
escalating rung to the matching technique in `auth-context/refs/auth_techniques.md`. De-dupe a
redirect_uri-to-external leak against the `open-redirect` skill.
