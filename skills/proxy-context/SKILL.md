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
- Requests kept **replay-faithful**: the full header set (including routing headers like **`Next-Action`**)
  and the **complete body — `multipart/form-data` bodies preserved verbatim** — so a captured RSC /
  server-action write replays byte-for-byte and can be tampered field-by-field (`_contract/proxy.md` §4a).
  These writes are **not reconstructable from scratch**; the capture *is* the only replayable copy.

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

**Replay-faithful capture (RSC / Next.js server-action writes).** A server-action POST carries a
`Next-Action: <id>` request header and a `multipart/form-data` body whose first part is the bound closure /
`prevState` arg — and it is **not reconstructable from scratch** (`_contract/proxy.md` §4a), so this captured
entry is the only replayable copy. Preserve it faithfully:
- keep the **`Next-Action`** header and the request `Content-Type` (with its multipart `boundary`) in
  `req.headers` — these are routing/structure, not secrets, so they are **not** redacted;
- keep the **full `req.body` verbatim**, including the multipart bound-state part — do **not** truncate or
  reflow it. Redaction swaps secret *values* (a token/password field's value → `‹redacted›`) only; it must
  leave the bound-state part and the part boundaries intact, or the entry no longer replays.

`scripts/replay_server_action.py` reads this entry and emits a replay template with id-swap / payload-inject
slots for the `xss-stored` / `bola-bfla` / `business-logic` / `race-condition` executors.

## Phases
- **Phase 1:** health + pull + normalize (read-only export).
- **Phase 2:** redact + consolidate + summary.

## Safety
Read-only **export** of already-captured traffic — this feeder sends no payloads of its own. In-scope hosts
only (`scope.yaml`); **redact** secrets before writing; the raw proxy project stays local (never committed).
Honor `_contract/proxy.md` + `_contract/roe-gate.md`. Audit-log.
