# Proxy Spine — route HTTP through an interception proxy (imported by every web-touching skill)

When an interception proxy is connected, **every HTTP request the engagement makes goes through it.** The
proxy is the engagement's HTTP **spine** and shared evidence store — *not* a fallback for a blocked fetch
(that is rung 3 of `anti-automation-ladder.md`; the spine sits **under** rungs 1–5 as the transport). Routing
through it makes every request **logged, searchable, scoped, reproducible, and reviewable by a human**,
instead of ephemeral traffic that vanishes when the turn ends.

**Optional but preferred.** With no proxy connected the framework runs exactly as before (the ladder's lower
rungs + `interactsh` for OOB). With one connected, the rules below apply. This is a layer *on top of*
`roe-gate.md`, never a replacement for it.

## 0. Engagement-start: ask for the proxy (do this FIRST)
**At intake — before recon, alongside scope + authorization — ASK the operator:** *"Is Burp or Caido running,
and on what host:port? I'll route all traffic through it so nothing is missed."* The ask is **mandatory** even
though the proxy stays optional (§ intro): you always ASK, the operator may decline. **Never silently skip
it** — a missed proxy means a missed Sitemap/History, and that is real surface lost (field lesson: a whole
second app on an in-scope host was invisible to the wordlist and sat in plain view in the proxy sitemap — §7).

- **If YES** — record the `host:port` endpoint, then wire the whole engagement through it **before the first
  request**:
  - export `HTTP_PROXY`/`HTTPS_PROXY` (and `NO_PROXY` for out-of-scope) **and set `RS_PROXY`** — the env var
    `scripts/rs_http.py` and the toolchain read to route bespoke probes through the same spine;
  - **trust the proxy CA**; generate the proxy's scope from `scope.yaml` (§6) so transport + scope gate agree;
  - route the toolchain through it: `curl -x`, `httpx -http-proxy`, `ffuf -x`, `nuclei -proxy`,
    `sqlmap --proxy`, `katana -proxy` (§3);
  - then **`proxy-context` ingests the proxy's Sitemap/History FIRST** (§7), before any brute-force.
- **If NO / none available** — proceed on the anti-automation ladder's lower rungs + `interactsh` for OOB
  (`anti-automation-ladder.md`), and **say plainly that proxy-only capture is unavailable**: no Sitemap
  mining, no replay-backed evidence, no human observability — so the operator can choose to start one.

This ask + wiring is the engagement's **first web-touching step**; it pairs with `roe-gate.md` §1–3a at intake
(scope · authorization · rate cap) and is recorded in the audit log (§6) either way (connected or declined).

## 1. The discipline it buys
- **Observability** — a human can open the proxy's History/Replay and *watch what the agent did*; the work is
  not trapped in a chat transcript.
- **Reproducibility** — a confirmation request is stored as a replayable entry, re-run byte-for-byte, instead
  of being regenerated from a prompt.
- **Scope at the transport** — the proxy won't forward an out-of-scope host even if the agent errs
  (defense-in-depth with the scope gate).
- **Shared source of truth** — the human and the agent see the same History, Sitemap, and Findings.
- **Reviewable evidence** — a finding points at a logged request/response pair, not a pasted `curl`.

## 2. Capabilities, not vendors (tool-first)
Target the **capability**; the operator picks the backend; **degrade gracefully** to the floor so nothing is
mandatory. (Name the capability in a skill step, e.g. "obtain an OAST payload" — not a product.)

| Capability | What it gives the engagement | Backends (any one) | Floor if none |
|---|---|---|---|
| **history** | searchable record of every request/response | Caido History · Burp proxy history · mitmproxy flows · ZAP | `logs/fetch.log` |
| **replay**  | re-send / tamper a stored request | Caido Replay · Burp Repeater / send-request | `curl` from the logged request |
| **oast**    | attributable out-of-band callback, auto-correlated to its request | Caido QuickSSRF · Burp Collaborator (Pro) | `interactsh-client` |
| **findings**| a shared place to file + export evidence | Caido Findings · Burp Scanner issues (read) | `findings.json` |
| **scope**   | transport-level allow/deny | Caido Scopes · (Burp scope) | `scope.yaml` + the scope gate |

Backends differ — design to the lowest common capability: Burp's send-to-Intruder only *opens a tab* (no
attack-start) and it has no scope/sitemap-list tool; Collaborator/Scanner are Pro-only. Caido exposes a
broader surface (Sitemap, Replay collections, Automate, Scopes). Never assume a backend-specific tool exists.

## 3. Route all traffic through it
When a proxy is connected, make the whole toolchain egress through it so one History holds everything:
- Export `HTTP_PROXY`/`HTTPS_PROXY` (and `NO_PROXY` for out-of-scope) and **trust the proxy CA**.
- `curl -x`, `httpx -http-proxy`, `ffuf -x`, `nuclei -proxy`, `sqlmap --proxy`, `katana -proxy` all honor it.
- Record in the audit log which requests went through the proxy (chain of custody).

## 4. Human-in-the-loop sends
A **state-changing or authentication** request is *proposed and staged*, and a human fires it — the proxy's
send-approval is an extra gate above `roe-gate.md` §2, not a replacement. Read-only sends (GETs, idempotent
probes) flow normally. **Redact** secrets (tokens, cookies, PII) to `‹redacted›` in anything exported or filed.

## 4a. Capture-once → replay/tamper (non-replayable RSC / server-action writes)
Some state-changing requests **cannot be synthesized from scratch** — notably React Server Component (RSC) /
Next.js **server-action** writes (login, profile/display-name update, build-manage). They POST to the page
with a **`Next-Action: <id>`** header and a **`multipart/form-data` body whose first field encodes the bound
closure / `prevState` argument**; that encoding is generated by the client bundle and can't be hand-built, so
a constructed `curl`/fuzzer POST returns a **500 `digest`** instead of exercising the action. A rung-2 `curl`
(`anti-automation-ladder.md` rung 3) therefore **cannot reach these writes at all** — which is why authed
server-action writes otherwise stay unprovable.

The method is **capture-once-through-the-spine, then replay/tamper** — mutate a *genuine* captured request
instead of synthesizing one:
1. Drive the write **one time in a real browser** (operator, or an authorized browser driver) **through the
   connected proxy**, so the real multipart `Next-Action` POST (headers + bound-state body) lands in History
   and is exported to `proxy-context/http_history.json` (§5). The entry must retain the multipart body + the
   `Next-Action` header so it is faithfully replayable (shape in `skills/proxy-context/SKILL.md`).
2. **Replay** that stored request byte-for-byte via the **replay** capability (§2 — Caido Replay / Burp
   Repeater; floor: `curl` built from the logged request), then **tamper the one field under test**: swap the
   object id (BOLA/IDOR **write**), inject the stored-XSS payload, mutate a price/quantity/state field, or
   fire the replay as a parallel burst (race). The bound-state field stays untouched, so the server still
   accepts the request.

This is what makes authed server-action writes **provable**: the executors (`xss-stored`, `bola-bfla`,
`business-logic`, `race-condition`) **source the request from `proxy-context/http_history.json`** rather than
constructing it. It **degrades to a human handing over one capture** when the browser driver is declined —
one captured request is all the replay needs. State-changing replays still obey §4 (proposed + staged, a
human fires) and `roe-gate.md`.

## 5. Export → the engagement
The **`proxy-context`** feeder exports the connected proxy's captured history to
`<engagement>/proxy-context/http_history.json` (shape in `skills/proxy-context/SKILL.md`). That export:
- **enriches the content map / Site Map** — real method·status·type·params·headers·body per URL (feeds
  `content-discovery`'s `content.json routes[]` and the console Site Map's request/response view);
- becomes **replay-backed evidence** — an executor's confirmation request is referenced by its history id so
  the independent reviewer verifies against the logged exchange.

Secrets are redacted on export; the raw proxy project stays local (never committed).

## 6. Scope + audit convergence
Generate the proxy's scope from `scope.yaml` so the transport layer and the scope gate **agree** (one scope,
two enforcement points). Every exchange is appended to the immutable engagement audit log §`roe-gate.md`.

## 7. Mine it as discovery (sitemap-first, before you brute-force)
The connected proxy's **Sitemap/History is a primary discovery source, not just an evidence store** — and
the cheapest one: it costs **zero extra requests** (it is traffic that already happened), so under a
stealth/rate cap it outranks brute-force. **Before** leaning on a wordlist, pull what the proxy already saw:
- A wordlist only finds paths you *thought to guess*; the sitemap holds the paths the app **actually
  loaded** — sub-apps, SPA mounts, API bases, embedded third-party widgets — that no generic list contains.
  (Field lesson: a whole second app on an in-scope host was invisible to a 140-word list and sat in plain
  view in the proxy sitemap.)
- `proxy-context` must **ingest the Sitemap/History first** and seed `content.json routes[]` + the
  `content-discovery` wordlist from it; brute-force then *extends* that real surface instead of guessing it
  cold. Treat every distinct path prefix in the sitemap as a **mount to recurse into** (§`content-discovery`).
- Keep the human browsing in the loop: a few minutes of operator browse-through the proxy enumerates more
  real surface than a long scan, and stays WAF-safe. Ask for / import their sitemap rather than re-deriving it.

A host is **not** "mapped" until the proxy sitemap has been mined — see `content-discovery` §coverage.

## 8. Sanity: did the proxy actually REACH it? (don't trust proxy output blindly)
A proxy can answer *for* an upstream it could not reach — Burp returns its own **"Burp Suite" landing/error
page** (often HTTP 200) when it can't connect (DNS failure, internal-only host, refused), and a transparent
proxy may serve a captive/error page. Taken at face value this **corrupts discovery**: an unreachable host
reads back as "200 + content". So **validate the transport before trusting a response**:
- A 2xx whose body is the *proxy's own* page (title "Burp Suite", a generic proxy error, a captive portal)
  is **not** the target — treat the host as **unreachable**, not live.
- When a result looks surprising (every host "200", a tech fingerprint that doesn't fit), **cross-check one
  host DIRECT** (no proxy). Direct-fails + proxy-"200" = the proxy is answering, not the host.
- The proxy is the spine for reachable, in-scope hosts; it is **not** a way to reach a host your own client
  can't — if direct and proxy both fail, the host is internal/blocked (record it as such, don't fabricate).
