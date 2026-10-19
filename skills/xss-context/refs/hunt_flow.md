# XSS hunt — end-to-end methodology, targeting, escalation
# The FAMILY-level playbook: how the feeder + the four variants (reflected / stored / dom / blind)
# compose into ONE hunt, WHERE to point it first, and how to turn a firing payload into earned
# severity. Payload/technique depth lives in the variant refs; this is the connective tissue
# (useful to the bug-bounty orchestrator's XSS routing and to any single-class XSS hunt).

## The hunt, end to end
0. **Scope + surface in** — `scope.yaml` (+ `oob.collaborator` for blind/stored) and `js-analysis/out/<site>/`.
1. **Map every reflection / sink surface** — not just query params. Headers (`Referer`/`User-Agent`/
   `X-Forwarded-For`/`Origin`), JSON keys *and* values, path segments, cookies, fragments, and
   *rendered API fields*. (feeder step 2; `injection_surface.md`.)
2. **Classify each point** — reflected / stored / dom / blind, with its context + CSP posture →
   `xss_context.json` `variant_hint[]`. (`context_rules.md`.)
3. **Baseline-probe discipline** — a unique random marker per (point, source); grep the baseline
   response for natural occurrences FIRST (a page that already contains your string is a false
   positive). A numeric/arithmetic canary (`rs<hex>` alongside `7*7`) also separates plain reflection
   from server-side *evaluation* — if `49` comes back, route to SSTI, not XSS.
4. **Fan out the four variants** — each already mechanical-gated + reviewer-verified:
   - reflected → `xss-reflected` (context breakout → WAF ladder).
   - stored → `xss-stored` (store→render map; the viewer's privilege IS the impact).
   - dom → `xss-dom` (source→sink taint; Trusted Types posture).
   - blind → `xss-blind` (OOB beacon; plant early, keep the listener up for a delayed fire).
5. **Confirm, don't assume** — reflected-but-encoded is NOT a bug; a DNS-only / plain-GET hit is NOT
   proof. The bar is execution in a real *current* browser, or an OOB beacon carrying a JS-derived
   value (`document.domain`). (`verify.md`.)
6. **De-dupe across the four** — one root cause found by several variants = one finding (the variants
   reconcile during their `verify.md` pass).
7. **Escalate → earn the severity** (catalog below), then **package** the submission
   (`bug-bounty/refs/report_quality.md` → `reporting`).

## Where to point it first (targeting)
XSS is cheap to find and cheap to dismiss — spend the budget where a fire becomes *impact*.
### High-value surfaces (hunt these first)
- Admin / settings / moderation consoles, and anything a **privileged viewer** renders (stored → cross-priv).
- Auth surfaces: sign-in, SSO / OAuth callback, password reset (DOM-XSS at a callback can capture a token).
- Payment / checkout / account-email flows (terminal impact is money or account takeover).
- Collaborative + stored content: comments, wikis, tickets, profiles, shared SaaS-tenant surfaces.
- File / SVG upload and anything served **same-origin** (an inline SVG/HTML upload is script execution).
### Asset priority
Main product origin → admin subdomains → APIs (rendered fields) → marketing / help / docs sites.
### Surface signals (from recon — route attention)
- Redirect / return-URL params (one-click reflected XSS); tracking / UTM / analytics params.
- Missing or weak CSP, missing `X-Content-Type-Options: nosniff`, permissive upload `Content-Type`.
- DOM sinks in the app's JS (`js-analysis` gadgets); client-side routers / hash handlers.
- Tech markers: markdown / documentation / diagram renderers, in-browser template engines,
  pinned framework versions (retire.js / `libraries.jsonl`).

## XSS escalation catalog — turn a fire into terminal impact
A bare `alert()` is Medium at best. Chain to a concrete loss, then rate to what was DEMONSTRATED —
benignly (benign marker / OOB token / `document.cookie.length`, never real user data).
| Primitive | Chain | Terminal impact |
|---|---|---|
| Reflected XSS on a cacheable response | + cache poisoning (unkeyed input cached, served to others) | persistent XSS at CDN / edge scale |
| Self-XSS (fires only in your own view) | + CSRF to force the victim to store/trigger it | effective stored XSS → ATO |
| DOM XSS on sign-in / OAuth callback | read the fragment / token the callback holds | auth-token capture → ATO |
| SVG / HTML upload served same-origin | + CSP bypass if one is present | same-origin cookie / session theft |
| postMessage XSS (weak / absent origin check) | exfil a cross-origin token the frame holds | cross-origin token exfil |
| Stored XSS rendered to an admin / privileged viewer | fires inside the privileged session | cross-privilege escalation / takeover |
Benign proof of each: a per-chain OOB token + `document.domain` (attributes the fire), or one scoped
action as the victim shown once — never a mass or destructive action. Stored payloads that can reach
real users are approval-gated + logged in `cleanup.md` for removal (SKILL §Safety).

## Severity rule (anti-inflation)
Do NOT rate XSS Critical without a DEMONSTRATED terminal impact (account takeover, token exfil,
privilege escalation, or mass / persistent reach). Reflected or DOM execution with no demonstrated
chain is Medium; stored-to-other-users is Medium–High by viewer privilege + blast radius. The claimed
CVSS must match what the PoC actually did (`reporting` + `verify.md` enforce this; see
`_contract/severity-calibration.md`).

## Root cause → where to grep (source-audit / remediation)
With source available (`source-audit`), or to frame remediation precisely:
| Root cause | Grep / signal |
|---|---|
| Output marked safe by hand | `html_safe`, `raw`, `mark_safe`, `\|safe`, `dangerouslySetInnerHTML`, `v-html`, `{{{ }}}` |
| A translation / view helper marks a string safe | i18n/helper returning a safe/raw string interpolated with user data |
| Allowlist keeps a dangerous tag/attr combo | sanitizer config `ADD_TAGS` / `ADD_ATTR`; svg / mathml allowed |
| Unsandboxed third-party renderer | markdown / diagram / doc renderer run on user text with no sanitize-after |
| `javascript:` not blocked in a URL field | `href` / `src` / `action` assembled from user input, no scheme allowlist |
| SVG / upload treated as non-script | upload handler with no `Content-Type` / extension enforcement, served inline |
| Reflected input gets cached | response caching on a path that reflects a param (cache-key / `Vary` gaps) |
| Incomplete sanitizer patch | pinned-old sanitizer version (retire.js / `libraries.jsonl`) with a known bypass |

All hunting is scope-gated + rate-limited (`roe-gate.md`); every confirmation is benign and
browser-verified. One root cause = one finding, escalated to the impact actually shown.
