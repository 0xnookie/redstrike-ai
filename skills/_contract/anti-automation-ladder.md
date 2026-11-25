# Anti-Automation / Fetch Escalation Ladder (shared primitive)

Imported by every web-touching skill (js-analysis, content-discovery, every vuln agent).
**Escalate only when the prior rung is blocked** — don't spin up a headless browser when `curl` works. Log which rung produced each artifact.

| # | Rung | Use when | Notes |
|---|---|---|---|
| 1 | `webfetch` | simple, static, unauthenticated | cheapest; no JS execution |
| 2 | `curl` (UA + headers + auth) | rung 1 blocked / needs headers, cookies, auth | set a realistic `User-Agent`, `Referer`, `Accept`; attach `auth.env` creds |
| 3 | **interceptor** (mitmproxy / Caido / Burp) + manual browse | rung 2 tripped by JS challenge / dynamic nav / needs a human-driven session; **required** for RSC / server-action writes (rung 2 can't encode the bound state) | capture the real traffic; replay |
| 4 | `chrome-devtools-mcp` (headless) | needs JS execution, Network capture, lazy-load | capture the Network panel; trigger lazy chunks |
| 5 | `puppeteer` / `playwright` (scroll + trigger) | SPA, infinite scroll, event-gated content, strongest bot defenses | scroll, hover, click to force-load; stealth as needed |

## Rules

- **Stay in scope.** Every rung obeys `roe-gate.md`. A fetch outside `scope.yaml` is a hard stop.
- **Respect blast radius.** Rate-limit; honor exclusion lists; default to passive/safe mode.
- **Tell a per-host policy deny apart from "you're blocked" (don't over-trip the circuit-breaker).** A
  **403 on one host** (or a specific path) is usually a *policy deny* — that resource is external-denied/
  internal — **skip it and keep going**; it is NOT a signal that the WAF is blocking *you*. The real
  **block** signals are: a **429** (rate limit), a 403/503 that **suddenly appears across hosts/paths that
  were just working**, or a **403 on a normally-public path** (e.g. `/robots.txt`) — i.e. the host denying
  your *client* wholesale. On a real block: **stop that host, back off, do not escalate rungs or disguise
  the client to get past it** (that is evasion, barred by `roe-gate.md` and any WAF-safe rule) — the
  WAF-safe path is to halt, not to beat the WAF. A browser-only target (a gateway that 403s every
  non-browser request, even through a proxy) is a hard boundary: hunt it from a real browser or not at all.
  - **Prevention, not just detection.** Before broad active work, fingerprint the WAF (`wafw00f`) and do NOT
    broadcast raw attack-signature payloads (`/etc/passwd`, `{{7*7}}`, SQL tautologies) across many hosts —
    those are exactly what trip an IP-reputation ban. Detection stays WAF-safe (benign canaries, encoded /
    low-signal probes, rate-capped); turning detection into a signature flood is how you lose the egress.
  - **An IP-reputation ban is ENGAGEMENT-WIDE, not per-host.** When the block is a sudden *estate-wide*
    403/429 shell — hosts that were just 200 now all blocked — your **egress itself** is banned, so the
    "stop that host" above does nothing here: **halt active work from that egress entirely** (field lesson:
    one signature flood flipped ~1200 recon-200 hosts to the WAF 403 shell off a single egress).
  - **Recovery is halt / back-off / rotate egress — never evade.** After an IP-ban: pause and let the ban
    lapse, or rotate to a fresh *authorized* egress and resume **gently + WAF-safe**. Disguising the client to
    beat the WAF stays barred (`roe-gate.md`); authorized evasion-to-exploit is a separate, scoped capability
    (`skills/waf-bypass/`), **not** a way to un-ban a burned IP.
- **Record provenance.** Each fetched artifact logs the rung that produced it (`logs/fetch.log`) for reproducibility and chain of custody.
- **Prefer the lowest rung that works.** Higher rungs are slower, louder, and more detectable.
- **RSC / server-action writes need rung 3 (capture), not rung 2.** A React Server Component / Next.js
  server action POSTs with a `Next-Action` header and a `multipart/form-data` body whose first field encodes
  the bound `prevState` arg — **rung-2 `curl` cannot encode that**, so a synthesized POST returns a 500
  `digest` and the write is unreachable from scratch. The **required** rung is **rung 3: capture the genuine
  request once through the proxy spine, then replay/tamper it** (`_contract/proxy.md` §4a). The executors
  (`xss-stored`/`bola-bfla`/`business-logic`/`race-condition`) source it from `proxy-context/http_history.json`
  rather than constructing the request.
- **Proxy spine (orthogonal):** rung 3's interceptor is a *fallback fetch*; when a proxy is connected as the
  engagement's HTTP **spine** (`proxy.md`) it sits *under* every rung as the transport, so all traffic lands in
  one searchable, replayable History. The `proxy-context` feeder exports that History into the engagement.
