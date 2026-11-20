# Browser Session Driver — autonomous login → navigate → action (shared primitive)

Imported by `browser-exploit` and by the stateful-write executors (`idor`, `bola-bfla`,
`business-logic`, `race-condition`, `auth-bypass`, `xss-stored`).
It is the contract for **driving a real browser autonomously** to carry out an authenticated,
state-changing flow end-to-end — so a browser-gated WRITE is *proven*, not flagged for a human.
It sits **on top of** `roe-gate.md` (authorization), `anti-automation-ladder.md` (rungs 4–5), and
`proxy.md` (the capture spine); it never replaces any of them.

Today `tooling.md` tells an agent to "flag the browser-gated tests for the human" when a flow needs a
real session, and `proxy.md` §4a degrades to "a human handing over one capture".
This contract is how an **authorized** agent performs that one drive **itself** — the single biggest cap
on autonomous yield for the stateful-write classes.

## When this applies (and when it does NOT)

Apply it when a state-changing action is **browser-gated** — reachable only from a real authenticated
browser session and not from a hand-built request:

- a login-gated **multi-step** workflow (checkout, transfer, coupon, profile/admin write);
- a **React Server Component / Next.js server action** write (`Next-Action` header + a
  `multipart/form-data` body whose first part is the bound `prevState` arg — not reconstructable from
  scratch, `proxy.md` §4a);
- a request whose body/token is **built by the client bundle** at runtime (JS-signed, DOM-derived CSRF);
- any flow whose state lives in the **DOM / client session**, not in a replayable URL.

Do NOT reach for it when a lower rung already works.
Per `anti-automation-ladder.md`, escalate to a browser **only when the prior rung is blocked** — if a
rung-2 `curl` or a rung-3 captured replay already proves the write, driving a browser is wasted blast
radius.
And it is **never** a way past a defense: if the only reason to drive a browser is to beat a block, stop
(see the RoE posture below).

## The driver capability (tool-first)

Target the capability **"drive a real browser"**; the operator picks the backend; degrade to the floor.

| Capability | What it gives the engagement | Backends (any one) | Floor if none |
|---|---|---|---|
| **browser-drive** | click/fill/submit/navigate a live page, read the DOM + console | `claude-in-chrome` (drives the operator's own Chrome) · `chrome-devtools-mcp` (headless) · `playwright` / `puppeteer` | the `proxy.md` §4a human/operator capture |

Drive whichever is connected through its own tool surface — **never hand-roll a browser**
(`tooling.md` tool-first rule).
Route the browser's traffic **through the connected proxy** (`proxy.md` spine) so every request lands in
one searchable, replay-faithful History — the genuine `Next-Action` / multipart capture is then available
to the owning executor for replay/tamper.

## The three phases: login → navigate → action

1. **Login** — establish the authenticated session in the real browser.
   Use **TEST accounts only** (`auth.env` / the per-account credentials the engagement materialized);
   never authenticate with found or real credentials.
   **Prefer to reuse the saved cookie-jar** from `content-discovery` (it logs in once and saves a
   Netscape / `MozillaCookieJar`) instead of re-authenticating each run — re-login per step is slow,
   noisy, and lockout-risky.
   When a fresh login is unavoidable, drive the real login form and **save** the resulting session to that
   same jar.

2. **Navigate** — walk the multi-step authenticated flow to the state-changing action, following the
   workflow map `content-discovery` built (the authed-vs-unauth surface diff + multi-step flow map).
   Each step is a **real browser action** (click / fill / submit) that is **observed** (DOM + network),
   not a blind POST — the point of a browser is that the client-built state is real.

3. **Action** — carry out the one state-changing action end-to-end.
   Capture the **before/after state** (the proof the write actually happened), keep the action **benign**
   (a test record / benign marker), and let the genuine request land in the proxy History
   **replay-faithfully** (`Next-Action` + multipart bound-state preserved) so the owning executor can
   replay and tamper exactly one field — swap the object id (`idor` / `bola-bfla`), inject the stored-XSS
   payload (`xss-stored`), mutate a price/quantity/step (`business-logic`), or fire the capture as a
   parallel burst (`race-condition`).

## Session-state drift between the HTTP tool and the browser (a documented failure mode)

The classic failure: the agent **logs in with the browser** (cookie-jar A) but then fires the
confirmation with an **HTTP tool** (`curl` / `httpx`, cookie-jar B) — the two sessions diverge and the
"proof" silently tests nothing.
Symptoms:

- the HTTP replay 401s or redirects to `/login` although the browser is plainly logged in;
- a CSRF / anti-forgery token (or a `Next-Action` bound-state) minted in the browser DOM is **stale or
  absent** in the hand-built request;
- the server **rotated** the session cookie in the browser, but the HTTP tool still carries the old one;
- `SameSite` / `Secure` / `HttpOnly` cookies the browser holds never reach the external jar.

Handling:

- **One source of truth for the session.** Pick a single cookie-jar and have **both** the browser and any
  HTTP tool read and write it — reuse `content-discovery`'s saved jar. After any browser action that
  rotates the session, **re-export the jar** before the next HTTP call.
- **Carry per-request anti-forgery state live.** Read a CSRF token / `Next-Action` bound-state **from the
  live DOM or the fresh capture** for each request; never reuse a stale one.
- **Prefer to stay in one lane.** If the flow is browser-gated, do the confirmation **in the browser** (or
  replay the browser's genuine captured request through the proxy) rather than hopping to a hand-built
  `curl` mid-session — cross-tool hops are the drift source.
- **Detect drift; do not mask it.** An unexpected 401 / redirect-to-login / anti-forgery reject right
  after a successful browser login is the **drift signal** — re-sync the jar/token.
  It is not a finding and not a reason to escalate rungs or disguise the client.

## RoE-honest posture — no fingerprint spoofing

- Every phase obeys `roe-gate.md` (scope, window, approval) and the `proxy.md` §4 human-in-the-loop send
  gate for state-changing sends — a state-changing drive is **proposed + staged**, and the operator can
  watch it in the proxy History.
- Driving a real browser is for **reaching a legitimately authorized flow**, never for **evading a
  defense**.
  Do **not** spoof the browser fingerprint, forge a `User-Agent` / TLS / JA3 signature, solve or bypass a
  CAPTCHA, or otherwise disguise the client to beat a WAF or bot-defense.
- A **real block** — a `429`, a `403`/`503` that suddenly appears across hosts/paths that were just
  working, a `403` on a normally-public path, or a WebSocket upgrade that resets with no HTTP status — is a
  **HALT-and-FLAG** signal (`anti-automation-ladder.md` + `roe-gate.md`).
  The WAF-safe path is to stop, not to out-automate the WAF.
  A **browser-only gateway** that 403s every non-browser request is a hard boundary: hunt it from a real
  **authorized** browser (the operator's own session) or not at all — never by faking one.
- TEST accounts and **benign markers** only; record and **revert** any test record created (the invoking
  skill's `cleanup.md`).

## Degradation (the floor is a human capture, never a spoofed client)

No browser driver is available, or the operator declines one → degrade to the `proxy.md` §4a
**capture → replay** path: a human (or an authorized browser session) drives the write **once** through
the proxy, and the executors replay that single genuine capture.
This capability's whole purpose is to make that one drive **autonomous**; its floor is the human capture —
it is **never** a hand-rolled, fingerprint-spoofed HTTP client.
