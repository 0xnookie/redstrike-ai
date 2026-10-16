# Anti-Automation / Fetch Escalation Ladder (shared primitive)

Imported by every web-touching skill (js-analysis, content-discovery, every vuln agent).
**Escalate only when the prior rung is blocked** — don't spin up a headless browser when `curl` works. Log which rung produced each artifact.

| # | Rung | Use when | Notes |
|---|---|---|---|
| 1 | `webfetch` | simple, static, unauthenticated | cheapest; no JS execution |
| 2 | `curl` (UA + headers + auth) | rung 1 blocked / needs headers, cookies, auth | set a realistic `User-Agent`, `Referer`, `Accept`; attach `auth.env` creds |
| 3 | **interceptor** (mitmproxy / Caido) + manual browse | rung 2 tripped by JS challenge / dynamic nav / needs a human-driven session | capture the real traffic; replay |
| 4 | `chrome-devtools-mcp` (headless) | needs JS execution, Network capture, lazy-load | capture the Network panel; trigger lazy chunks |
| 5 | `puppeteer` / `playwright` (scroll + trigger) | SPA, infinite scroll, event-gated content, strongest bot defenses | scroll, hover, click to force-load; stealth as needed |

## Rules

- **Stay in scope.** Every rung obeys `roe-gate.md`. A fetch outside `scope.yaml` is a hard stop.
- **Respect blast radius.** Rate-limit; honor exclusion lists; default to passive/safe mode.
- **Record provenance.** Each fetched artifact logs the rung that produced it (`logs/fetch.log`) for reproducibility and chain of custody.
- **Prefer the lowest rung that works.** Higher rungs are slower, louder, and more detectable.
