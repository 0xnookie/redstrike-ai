# Per-class chain anchors (FEEDER discipline)
# Reference for attack-chain-discovery's missing-leg hypothesis loop. For composition over EXISTING accepted
# findings this is passive reasoning; the moment it drives a scoped PROBE it is ACTIVE → honor the SKILL's
# approval gate (`_contract/roe-gate.md`) and run the ONE named Tier-2 executor + its `*-verify` reviewer.

## The feeder rule
A CONFIRMED (reviewer-accepted) finding in any class below is **a FEEDER, not a report**. Before the chain
engine treats such a finding as terminal, it MUST probe the listed anchors — the specific next things that turn
a modest primitive into a kill chain. An anchor that returns signal is a chain candidate: hypothesize the
missing leg, gate it, dispatch the ONE Tier-2 executor that can confirm it, and promote the chain only if that
executor's `*-verify` reviewer returns `accepted` (SKILL steps 4-7). If every anchor fails, the finding stays
at its standalone severity — several of these classes are low/informational ALONE and only earn their rating
once chained. Never emit a chain whose leg was assumed; a dropped hypothesis is recorded in `probes.json`, not
surfaced as a chain.

How to read each block: the class (the accepted feeder) → the 5-6 anchors to probe → the Tier-2 executor each
anchor routes to for confirmation (parenthesized `redstrike-<class>`).

---
## `open-redirect` — anchors
Standalone external redirect is low-impact. Probe:
1. **OAuth/OIDC `redirect_uri` reflection** — for every OAuth client on the target, try the redirect against your
   controlled domain; if the auth `code` is delivered to it → ATO chain. (`oauth`)
2. **`returnTo` / `next` / `continue` after auth** — submit a `javascript:`/external value; if the SDK does
   `location.href = returnTo`, it executes or leaks post-login. (`oauth` / `auth-bypass`)
3. **SAML `RelayState` / OIDC `post_logout_redirect_uri`** — external or markup value accepted in the SSO flow. (`oauth`)
4. **Post-login redirect + login CSRF** — if the redirect fires after login, login-CSRF onto an attacker target
   becomes an ATO primitive. (`csrf` → `auth-bypass`)
5. **Sibling-subdomain redirect target** — if it points at a subdomain you can influence, it enables a cookie /
   token-handoff chain. (`subdomain-takeover`)
6. **Token/`code` in the redirected URL** — any secret in the query of the external hop is directly stealable. (`oauth`)

---
## `cors` (CORS misconfig) — anchors
A permissive ACAO alone is informational. Probe:
1. **Credentialed endpoint** — an authed endpoint with `Access-Control-Allow-Credentials: true`; without creds
   reflected, the misconfig is cosmetic. (`cors`)
2. **Sensitive-data endpoint reach** — does the reflected origin read `/api/me`, user records, billing, tokens?
   Document the exact data a cross-origin read exfiltrates. (`cors` → `bola-bfla` / `idor`)
3. **`Origin: null`** — sandboxed-iframe / `data:` origins expose weak allow-list logic. (`cors`)
4. **Allow-list regex flaw** — `target.tld.attacker.tld`, `nottarget.tld`, `target.tld\.attacker.tld` to break a
   loose origin check. (`cors`)
5. **Unvalidated `postMessage` handler** — a `window.addEventListener('message', …)` with no origin check is the
   data-theft sink that pairs with a cross-origin reader. (`xss-dom`)
6. **Secret in the CORS-readable body** — an API key / token in the response the attacker origin can now read. (`secrets`)

---
## `info-disclosure` (secrets / exposed surface / verbose errors) — anchors
Standalone disclosure is rarely reportable unless chained. Probe:
1. **Secret in a JS bundle / source map / config** — OAuth `client_secret`, API key, signing key → `oauth`
   (client_secret + missing PKCE = code interception) or `jwt` (signing key → forgery). (`secrets` → `oauth` / `jwt`)
2. **Stack trace leaking internal IPs / service names / hostnames** — now you know what to aim SSRF at. (`ssrf-inband` / `ssrf-blind`)
3. **Debug/echo endpoint returning request headers or sessions** — session/IDOR candidate. (`idor` / `auth-bypass`)
4. **`.git` / `.env` / `backup.*` / `wp-config.*` exposed** — DB creds → privesc; signing keys → JWT/alg confusion. (`exposed-surface` → `privesc` / `jwt`)
5. **API key with live, over-broad scope** — verify the scope; if it reaches other-user data → IDOR-via-key. (`secrets` → `idor`)
6. **Cloud metadata reachable from an in-page fetch/SSRF context** — IMDS credential theft. (`ssrf-cloud`)

---
## `csrf` — anchors
CSRF on an isolated form is low/medium. Probe the action it changes:
1. **Password / email / phone change** → account takeover (alters the recovery vector). (`auth-bypass`)
2. **MFA disable / second-factor enrollment** → MFA bypass. (`auth-bypass`)
3. **Role change / permission grant / team invite** → privilege escalation. (`privesc`)
4. **Payment-method / withdrawal-address change** → financial impact. (`business-logic`)
5. **OAuth client registration / API-key creation** → persistent backdoor-credential chain. (`oauth` / `secrets`)
6. **State-change that later renders to a higher-priv user** → CSRF-to-stored-XSS-in-admin pivot. (`xss-stored`)

---
## `subdomain-takeover` — anchors
Standalone takeover is medium without a chain. Probe:
1. **Subdomain is an OAuth `redirect_uri` / SAML ACS / OIDC issuer** — claim → token delivery → ATO. (`oauth`)
2. **Parent shares cookies (`.target.tld`)** — claimed subdomain enables cookie-set / fixation on the parent. (`auth-bypass`)
3. **Subdomain holds a wildcard cert** — TLS-confusion / interception angle. (`tls-attacks`)
4. **Subdomain referenced from prod JS** (CDN / asset / config host) — trusted-domain phishing or script delivery. (`secrets` / `xss-stored`)
5. **Subdomain in the parent's CSP `script-src`** — claiming it defeats the CSP → escalates a reflected/stored XSS. (`xss-stored`)
6. **Subdomain terminates an email/SPF/DKIM record** — spoof-mail or reset-link chain. (`business-logic`)

---
## `xxe` — anchors
In-band file read alone is often informational on cloud hosts. Probe:
1. **SSRF via XXE → cloud metadata** (`SYSTEM "http://169.254.169.254/…"`) → IAM creds → infra compromise. (`ssrf-cloud`)
2. **OOB exfil to an attacker DTD** — blind read of config / private files when in-band is blocked. (`xxe-blind`)
3. **SAML-assertion XXE** — parser abuse during assertion handling → auth-flow impact. (`auth-bypass` / `oauth`)
4. **DOCX / XLSX / SVG upload carrying XXE** — payload survives the pipeline and fires in an internal viewer
   (admin context). (`upload-rce` → `xxe-blind`)
5. **PHP / Java wrapper reach** — `php://filter/convert.base64-encode/…` to read source; `jar:` / `ldap:` toward
   classloader RCE (benign OOB proof first). (`xxe-inband` / `deserialization`)
6. **Internal HTTP reach beyond metadata** — admin panels / unauthenticated internal APIs the entity can hit. (`ssrf-inband`)

---
## `file-upload` — anchors
Beating an extension/MIME check is informational unless the file lands somewhere useful. Probe:
1. **Upload to web root + executable** → web shell → RCE. (`upload-rce`)
2. **SVG / HTML rendered inline** → stored XSS in the viewer context. (`xss-stored`)
3. **Path traversal in the filename** → overwrite config / cron / `authorized_keys` → privesc / RCE. (`path-traversal-lfi` → `privesc`)
4. **Filename / EXIF / metadata renders in an admin panel** → stored XSS in admin context → ATO. (`xss-stored`)
5. **Upload triggers a server-side processor** (PDF render, image resize, AV) → SSRF / processor-CVE RCE. (`ssrf-inband` / `cve-intelligence`)
6. **Content-type confusion to a parser sink** (e.g. an XML-parsing processor) → XXE. (`xxe-inband`)

---
## `race-condition` — anchors
A race on a low-impact action is low. The multiplier is WHAT races:
1. **Financial action** (transfer / withdrawal / debit) → quantify the dollar amount. (`business-logic`)
2. **Coupon / gift-card / referral redemption** → quantify (free value × N). (`business-logic`)
3. **One-shot token** (password-reset / invite / MFA-enroll) → double-redeem → ATO. (`auth-bypass`)
4. **TOCTOU on a file-write / check** → privesc / RCE. (`privesc`)
5. **Rate-limit / quota check** → bypass → mass enumeration / IDOR amplification. (`idor` / `bola-bfla`)
6. **Limit-overrun via API batching/aliasing** (counter counts the wrong unit) → same overrun as concurrency. (`bola-bfla`)

---
## `business-logic` — anchors
Price/coupon/workflow manipulation needs impact quantification. Probe:
1. **Manipulated artifact shown to a higher-priv user** (public archive / share-with-admin) — does it render where
   it becomes source-of-truth? (`privesc` / `xss-stored`)
2. **Tampered value persists server-side** and re-renders in an admin/settlement view → authz/impact pivot. (`idor`)
3. **Workflow skip → access a feature you didn't pay for** — quantify (premium feature × users). (`auth-bypass`)
4. **Negative / huge values → integer overflow / sign flip** → financial chain. (`business-logic`)
5. **Time-of-check / time-of-use on a balance** → race-condition chain. (`race-condition`)
6. **Replayed payment/success callback** — re-use a paid order reference for a new benefit. (`business-logic`)

---
## `privilege-escalation` — anchors
Vertical privesc is usually terminal — but confirm the blast radius:
1. **Mass-assignment set role / permission / tenant** — does the escalated account then see other-tenant data? →
   IDOR amplification. (`idor` / `bola-bfla`)
2. **JWT claim manipulation works** — check which other claims (`sub`, `aud`, `iss`, `tenant`) are unprotected →
   cross-tenant chain. (`jwt`)
3. **Admin endpoint reachable but rate-limited** — confirm WRITE actions, not just GET. (`privesc`)
4. **Forced-browsing an admin URL works** — test `DELETE` / `PATCH` / `PUT` too, not only reads. (`bola-bfla`)
5. **HTTP method-override bypasses authz** — re-try the same trick on every other admin endpoint. (`bola-bfla`)
6. **Escalated role unlocks a new tool/integration** (API-key mint, webhook) → persistent-credential chain. (`secrets`)

---
## Deep-chain examples (real shapes the engine should recognize)
These show anchors composing end-to-end. Each LEG must still be an accepted finding before the chain is emitted.

- **open-redirect → OAuth `redirect_uri` → ATO.** An accepted open-redirect's controllable destination is pointed
  at the OAuth client's `redirect_uri`; probing anchor 1 confirms the auth `code` is delivered to the attacker
  domain; exchanging the code yields account takeover. (legs: `open-redirect` + `oauth`)

- **info-disclosure → secret-in-bundle → SSRF/.git → privesc.** A JS bundle / source map leaks an internal
  service host and an OAuth `client_secret` (anchors 1-2); the host feeds a confirmed SSRF toward an internal
  admin API, OR an exposed `.git` / `.env` leaks DB/signing material; either lands on privilege escalation.
  (legs: `secrets`/`exposed-surface` + `ssrf-inband` (or `jwt`) + `privesc`)

- **S3/bucket listable → client_secret in JS → no PKCE → redirect_uri intercept → ATO.** Four accepted legs:
  public listing exposes bundles, bundles carry the OAuth secret, the token endpoint doesn't enforce PKCE, a
  manipulated `redirect_uri` intercepts the code. (legs: `exposed-surface` + `secrets` + `oauth`)

- **subdomain-takeover → cookie handoff → session fixation → ATO.** A dangling CNAME is claimable (feeder);
  the parent shares cookies (anchor 2); a set-cookie from the claimed subdomain fixes a known session; the
  victim authenticates into it. (legs: `subdomain-takeover` + `auth-bypass`)
