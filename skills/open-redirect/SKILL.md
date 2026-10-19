# Open Redirect Agent

> ATOMIC single agent (no feeder) — one confirmation: a request param drives a redirect to an
> attacker-controlled EXTERNAL destination.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md`; carries `review.md` + `verify.md`.

## Interview
- **STEPS:** collect redirect params → probe redirect behavior → test payloads + allowlist bypass → confirm external redirect → note impact chains → rate → emit → review → verify.
- **TOOLS:** `curl -I`/`httpx` (follow + inspect `Location`), `chrome-devtools-mcp` for client-side redirects, interceptor; `jq`.
- **GOAL:** Confirm open redirect — a param sends the browser to an attacker-chosen external origin (server 3xx or client-side) — and flag impact chains (SSO/OAuth token leak, SSRF, `javascript:`→XSS). Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `redirect_params.json`, `redirect_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/out/<site>/findings/{params,endpoints}.jsonl` (redirect-ish params), `scope.yaml`. `refs/` = `redirect_payloads.md`. Chains FROM `js-analysis`; chains TO `reporting` (and flags for SSRF/XSS agents).
- **DECOMPOSITION:** n/a (atomic). Often a *primitive* for other bugs — cross-reference SSRF, XSS (`javascript:`), and auth (token leak).

## Goal
Find params that redirect to attacker-controlled external destinations; confirm and rate (with chain
impact). Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` all `- [x]` · `review.md` PASS · every finding accepted.

## What do we want
- Redirect-driving params (`redirect`, `next`, `url`, `return`, `callback`, …)
- Redirect mechanism: server `Location` 3xx / JS `location` / `meta refresh`
- Which payloads bypass any allowlist; what the redirect enables downstream

## Steps  (action · tool · output)
1. Collect redirect params (js-analysis param groups + observed) · `jq params.txt` · `redirect_params.json`
2. Probe mechanism per param · `curl -I` + `chrome-devtools-mcp` · (into tests)
3. Test payloads + allowlist bypass · `refs/redirect_payloads.md` · `redirect_tests.jsonl`
4. Confirm external redirect (Location/host = attacker) · `curl`/browser · `poc/<id>/`
5. Note impact chains (OAuth/SSO token leak, SSRF, `javascript:`→XSS) · synth · (into findings)
6. Rate (CVSS) + write finding · synth · `findings.json`
7. Emit report + curl · synth · `report.md`, `curl_commands.sh`
8. /REVIEW · `review.md` · 9. /VERIFY · `verify.md`

## Tools
- **Probe/confirm:** `curl -I`, `httpx`, `chrome-devtools-mcp` (client-side), interceptor
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/`: `params.txt`, `endpoints_*.txt`
- `scope.yaml`, `refs/redirect_payloads.md`

## Outputs
`redirect_params.json` · `redirect_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** collect params + mechanism probe.
- **Phase 2 (target-specific):** payload/allowlist-bypass + external-redirect confirmation + chain impact + rating.

## Safety
Low-impact, non-destructive probing — but redirect payloads leave scope by definition (they point
off-site to YOUR host). Use your own OOB/benign host; scope-gate the target requests; audit-log.
