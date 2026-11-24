# CRLF Injection Agent  (HTTP response splitting / header injection — CWE-113)

> ATOMIC single agent — CR/LF into a user value that reaches an HTTP RESPONSE HEADER sink
> (`Location` / `Set-Cookie` / a custom header), so an attacker adds or overrides a response header, or
> splits the header block to start a SECOND HTTP response. The HTTP-RESPONSE variant of CRLF injection
> (CWE-93); distinct from the email-header variant (`email-injection`).
> ACTIVE (sends HTTP requests carrying CR/LF), findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.

## De-dup boundary (what this skill OWNS vs hands off)
- **OWNS — HTTP response-header injection / response splitting:** a user-controlled value reaching a
  RESPONSE HEADER sink (`Location` from a redirect param, `Set-Cookie`, a reflected custom/`X-` header)
  WITHOUT CR/LF stripping, letting the attacker ADD or OVERRIDE a response header, or split the header
  block (`%0d%0a%0d%0a`) to start a second HTTP response — PROVEN by the injected header/marker appearing
  in the RESPONSE HEADER block (not merely reflected in the body) OR a genuine response-split start-line
  being parsed, and by causality (removing the CR/LF restores the normal response / drops the header).
- **HANDS OFF:** a payload that lands/executes in the response **BODY** (reflected/stored HTML/JS) is a
  **different class** → `xss-*`; an attacker controlling the redirect **destination/host** in the
  `Location` value (not a header split) → `open-redirect` / `host-header`; a poisoned response that a
  shared cache serves **cross-user** → `cache-poisoning` (confirm that leg there); CR/LF into a generated
  **email** header block (`Bcc`/`Reply-To`/MIME) → `email-injection`.
- A request that merely **returns 200/302** after a CRLF-ish payload (no validation error) is NOT a
  finding — this skill must show the injected header TOOK EFFECT in the response-header block, or a real
  second response started.

## Interview
- **STEPS:** ingest params/endpoints that reach a response-header sink from `content-discovery` + `injection-context` + `js-analysis` → identify the header sink per param (redirect→`Location`, session/pref→`Set-Cookie`, reflected request value→custom header) → inject CR/LF-breaking sequences (LF-only → CRLF → encoded → double-encoded → null-byte-prefixed) benignly with a unique cache-buster → confirm the injected header/marker appears in the RESPONSE HEADER block OR a response-split start-line is parsed, and that removing the CR/LF restores the normal response → rate → emit → review → verify.
- **TOOLS:** interceptor, `curl -sD-`/`jq` (read RAW response headers + status line), OOB collector (`interactsh`), `refs/crlf_injection.md`; hand body-landing to `xss-*`, redirect-host control to `open-redirect`/`host-header`, shared-cache impact to `cache-poisoning`, the email-header variant to `email-injection`.
- **GOAL:** Confirm HTTP response-header injection / response splitting — a user-controlled value breaks into the RESPONSE HEADER block so an attacker-chosen header takes effect, or a second HTTP response starts — proven benignly and causally (CR/LF removal restores normal). Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `crlf_tests.jsonl`, `callbacks.jsonl`, `findings.json`, `poc/`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = `content-discovery/` (params + endpoints + the observed response-header behaviour) + `injection-context/injection_context.json` (reflective sinks + injectable param candidates) + `js-analysis/out/<site>/findings/{endpoints,params}.jsonl` (redirect/header-reflecting params) + `scope.yaml` (`oob.collaborator`). `refs/` = `crlf_injection.md`. Chains FROM recon; chains TO `reporting` (+ `xss-*` / `cache-poisoning` / `open-redirect`-`host-header` for the downstream leg of a split).
- **DECOMPOSITION:** n/a (atomic).

## Goal
Prove HTTP response splitting / header injection, benignly: an attacker-controlled value broke into the
RESPONSE HEADER block so an injected header/marker is present in the response-header set, or a second HTTP
response start-line is parsed — and removing the CR/LF restores the normal response. Emit `findings.json`
(`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## What do we want
- The params/endpoints whose value reaches a RESPONSE HEADER sink (`Location` from redirect params,
  `Set-Cookie`, a custom/`X-` header that reflects a request value)
- A header break that TOOK EFFECT in the RESPONSE: an injected `X-`/`Set-Cookie` marker header present in
  the raw response-header block, OR a split that starts a genuine second `HTTP/1.x NNN` response
- Benign + CAUSAL proof — the raw response headers (captured with the CR/LF payload) vs the baseline
  (payload without CR/LF), showing the marker header/second response appears ONLY with the CR/LF; a unique
  cache-buster so only our own request is affected

## Steps  (action · tool · output)
1. Ingest params/endpoints that reach a response-header sink + classify the sink per param · `jq` recon + `curl -sD-` · (into tests)
2. Baseline the normal response headers per candidate (no CR/LF) · `curl -sD-` · `crlf_tests.jsonl`
3. Header-add probe: inject `%0d%0aX-CRLF-Test:<marker>` (then LF-only `%0a`, then double-encoded `%250d%250a`, then null-byte-prefixed) into the param · `curl`/interceptor · `crlf_tests.jsonl`
4. `Set-Cookie` injection probe: inject `%0d%0aSet-Cookie:<marker>=1` · `curl`/interceptor · `crlf_tests.jsonl`
5. Response-split probe: inject `%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK...` with a unique cache-buster (self-scoped) · `curl`/interceptor · `crlf_tests.jsonl`
6. Confirm TOOK EFFECT: parse the RAW response — marker header present in the header block, or a second `HTTP/1.x` start-line parsed; attributable OOB if the split causes a server-side beacon · `curl -sD-` + OOB · `callbacks.jsonl`
7. Causality check: re-send without the CR/LF — the marker header/second response MUST disappear (differential) · `curl -sD-` · `poc/<id>/`
8. Rate (CVSS) + write finding · synth · `findings.json`
9. Emit report · synth · `report.md`
10. /REVIEW · `review.md` · 11. /VERIFY · `verify.md`

## Tools
- interceptor, `curl -sD-`/`jq` (RAW response headers + status line — body reflection alone is not this class), OOB collector (`interactsh-client`), `refs/crlf_injection.md`
- hand off: body-landing reflection/stored → `xss-*`; redirect destination/host control → `open-redirect`/`host-header`; shared-cache cross-user impact → `cache-poisoning`; the email-header variant → `email-injection`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `content-discovery/` (params + endpoints + observed response-header behaviour) + `injection-context/injection_context.json` (reflective sinks + injectable param candidates)
- `js-analysis/out/<site>/findings/{endpoints,params}.jsonl` (redirect params + header-reflecting request values)
- `scope.yaml` (`oob.collaborator`), `refs/crlf_injection.md`

## Outputs
`crlf_tests.jsonl` · `callbacks.jsonl` · `findings.json` · `poc/` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** header-sink mapping per param + baseline response-header capture + the LF-only/CRLF/encoded/double-encoded/null-byte probe set.
- **Phase 2 (target-specific):** header-add + `Set-Cookie` + response-split confirmation (marker in the header block / parsed second start-line) + causality differential + rating (approval-gated).

## Safety
Sending a CRLF payload is an **active** test — **approval-gated**; confirm with BENIGN effects only (a
single benign marker header such as `X-CRLF-Test`, a self-scoped `Set-Cookie` marker — never a malicious
header). A response SPLIT can poison a shared cache or be served to another user: **always** use a unique
cache-buster so only our own request is affected, **never** inject a full malicious second response that a
shared cache would store and serve to real users, and if a cache/CDN sits in front, confirm the split in
isolation and **hand the cross-user cache impact to `cache-poisoning`** (de-dupe). Body-landing payloads
(→ `xss-*`), redirect-host control (→ `open-redirect`/`host-header`) and the email-header variant
(→ `email-injection`) are handed off. Redact any secret a captured header carries to a fingerprint. Kill
switch; scope to authorized endpoints; rate-limit; audit-log. Note: raw-header CR/LF is of **declining
prevalence** (modern servers/frameworks strip it) — do not inflate a body-only reflection into a
response-split claim.
