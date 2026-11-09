# Proxy Context — export the interception proxy's captured traffic

> TIER-1 recon feeder. Export the connected proxy's HTTP history → `http_history.json` (real request/response
> per URL, **secrets redacted**). Enriches the content map + Site Map and becomes replay-backed evidence.
> Honors `_contract/proxy.md` + `_contract/roe-gate.md`. Read-only export — emits NO findings → `review.md` only.

## Interview
- **STEPS:** confirm a proxy is connected (health) → pull captured History for in-scope hosts → normalize each exchange (method/path/status/type/params/headers/body/timing) → **redact secrets** → write `http_history.json` + `summary.md` → review.
- **TOOLS:** the connected proxy's history/export capability (Caido History · Burp proxy history · `mitmproxy` flow dump · ZAP) via its MCP/SDK/CLI; `jq` to shape. Tool-first — `_contract/proxy.md` + `_contract/tooling.md`.
- **GOAL:** a structured, redacted export of what the proxy has already seen (agent + human browsing), so the surface views and executors read **real traffic** instead of re-crawling. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `http_history.json`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = the live proxy project (operator-connected) + `scope.yaml` (in-scope filter). `refs/` = `proxy_refs.md`. Chains FROM the operator (who connected + browsed the proxy); chains TO `content-discovery` (site map / routes), `js-analysis`, every `<class>-context` feeder, and the vuln executors (replay-backed confirmation).
- **DECOMPOSITION:** n/a (recon feeder).

## Goal
A redacted `http_history.json` of the proxy's captured traffic. DONE = `checklist.md` `- [x]` · `review.md` PASS.

## What do we want
- Every in-scope request/response the proxy captured (agent + human-driven browsing), normalized.
- Secrets redacted (tokens, cookies, PII → `‹redacted›`).
- A per-host/route summary that seeds the content map + the console Site Map (request/response view).

## Steps  (action · tool · output)
1. Health-check the connected proxy · proxy capability · (gate: **no proxy ⇒ SKIP** — write an empty `http_history.json` + note, pass)
2. Pull captured History, **in-scope hosts only** · proxy history/export · (raw)
3. Normalize each exchange (method/path/status/mime/params/headers/body/timing) · synth + `jq` · (shaped)
4. **Redact** secrets/PII → `‹redacted›` · synth · (safe)
5. Consolidate · synth · `http_history.json`
6. Emit summary · synth · `summary.md`
7. /REVIEW SKILL · `review.md`

## Tools
- Proxy history/export capability (Caido · Burp · `mitmproxy` · ZAP) via its MCP/SDK/CLI — `_contract/proxy.md`.
- `jq` to shape; `_contract/tooling.md` tool-first rule (don't hand-roll a proxy — drive the one that's connected).

## Inputs
- The connected interception proxy (operator-connected; see `_contract/proxy.md`), `scope.yaml`, `refs/proxy_refs.md`.

## Outputs
`http_history.json` · `summary.md` · `logs/`

### `http_history.json` shape
Tolerant — `exchanges[]`, each a captured request/response. `host`+`path`+`method` are the keys the Site Map
merges on; `status`/`mime`/`params` drive its facets; `req`/`res` carry the raw message for the viewer.
```jsonc
{
  "engagement": "<id>", "generated_at": "<ISO-8601>",
  "source": "caido",                   // caido | burp | mitmproxy | zap | manual
  "exchanges": [
    { "id": "h1",
      "host": "app.acme.io",            // hostname (port optional)
      "method": "POST",                 // verb
      "path": "/v1/login",              // pathname (+ query when meaningful)
      "status": 200,                    // response status
      "mime": "application/json",       // response content-type
      "length": 812, "ms": 120, "ts": "<ISO-8601>",
      "params": ["email", "password"],  // params observed on this request
      "req": { "headers": [["Content-Type", "application/json"]], "body": "{\"email\":\"…\"}" },
      "res": { "headers": [["Set-Cookie", "sid=‹redacted›; HttpOnly"]], "body": "{\"ok\":true}" },
      "note": "login", "finding": "ACM-1001" // optional: recon note / linked finding id
    }
  ]
}
```
**Redact** every secret/cookie/token/PII to `‹redacted›` before writing. A legacy flat array of exchanges is
parsed tolerantly, but prefer the `{ "exchanges": [ … ] }` object above.

## Phases
- **Phase 1:** health + pull + normalize (read-only export).
- **Phase 2:** redact + consolidate + summary.

## Safety
Read-only **export** of already-captured traffic — this feeder sends no payloads of its own. In-scope hosts
only (`scope.yaml`); **redact** secrets before writing; the raw proxy project stays local (never committed).
Honor `_contract/proxy.md` + `_contract/roe-gate.md`. Audit-log.
