# Proxy Context — references

Export the connected interception proxy's captured traffic into the engagement. The proxy is the HTTP
**spine** (`_contract/proxy.md`), not a one-off fetch tool. This feeder only **reads/exports** — it sends
nothing of its own.

## Backends (pick what's connected; target the capability, not the product)
| Backend | History export | Notes |
|---|---|---|
| Caido | History (+ Sitemap, Replay) via its MCP server / client SDK | broad surface: Scopes, Replay collections, Automate, Findings |
| Burp | proxy HTTP history (+regex) via the official MCP server | per-send + data-access **approvals**; Collaborator/Scanner are Pro-only; no scope/sitemap-list tool |
| mitmproxy | `mitmdump -w flows` → read flows (floor, dependency-free) | scriptable export; no UI session |
| ZAP | History via its API | — |

Drive whichever is connected through its MCP/SDK/CLI — never hand-roll a proxy.

## Route the whole toolchain through the proxy
So one History holds everything the engagement touched:
```bash
export HTTP_PROXY=http://127.0.0.1:8080  HTTPS_PROXY=http://127.0.0.1:8080
export NO_PROXY="$(out-of-scope hosts)"
# trust the proxy CA for TLS (path depends on the backend), then:
curl -x "$HTTP_PROXY" …            # httpx -http-proxy · ffuf -x · nuclei -proxy · sqlmap --proxy · katana -proxy
```

## Normalize → `http_history.json`
One `exchanges[]` record per captured request/response (shape + fields in `SKILL.md`). Keys the Site Map
merges on: `host` + `path` + `method`; facets: `status`, `mime`, `params`; the raw `req`/`res` drive the
console's request/response viewer.

## Redaction (before writing — non-negotiable)
Replace every secret with the literal `‹redacted›`:
- `Authorization`, `Cookie`/`Set-Cookie`, `X-API-Key`, bearer/session tokens
- password / secret / token / key fields in bodies
- PII: emails (keep a test alias), card/SSN/IBAN, crypto wallets
The raw proxy project stays **local** — only the redacted `http_history.json` lands in the engagement.

## What consumes this
- `content-discovery` — folds real routes (method/status/type/params) into `content.json` / the Site Map.
- `js-analysis`, every `<class>-context` feeder — real endpoints/params instead of guesses.
- the vuln executors — reference a history id as **replay-backed evidence** for the independent reviewer.
