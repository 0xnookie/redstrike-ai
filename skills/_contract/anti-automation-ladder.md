# Anti-Automation / Fetch Escalation Ladder (shared primitive)

Imported by every web-touching skill (js-analysis, content-discovery, every vuln agent).
**Escalate only when the prior rung is blocked** — don't spin up a headless browser when `curl` works. Log which rung produced each artifact.

| # | Rung | Use when | Notes |
|---|---|---|---|
| 1 | `webfetch` | simple, static, unauthenticated | cheapest; no JS execution |
| 2 | `curl` (UA + headers + auth) | rung 1 blocked / needs headers, cookies, auth | set a realistic `User-Agent`, `Referer`, `Accept`; attach `auth.env` creds |
| 3 | **interceptor** (mitmproxy / Caido / Burp) + manual browse | rung 2 tripped by JS challenge / dynamic nav / needs a human-driven session | capture the real traffic; replay |
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
- **Record provenance.** Each fetched artifact logs the rung that produced it (`logs/fetch.log`) for reproducibility and chain of custody.
- **Prefer the lowest rung that works.** Higher rungs are slower, louder, and more detectable.
- **Proxy spine (orthogonal):** rung 3's interceptor is a *fallback fetch*; when a proxy is connected as the
  engagement's HTTP **spine** (`proxy.md`) it sits *under* every rung as the transport, so all traffic lands in
  one searchable, replayable History. The `proxy-context` feeder exports that History into the engagement.
