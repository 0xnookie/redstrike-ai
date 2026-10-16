# CORS Misconfiguration Agent

> ATOMIC single agent (no feeder) — one confirmation: a cross-origin, credentialed read of
> sensitive data enabled by a reflected/over-permissive ACAO.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md`; carries `review.md` + `verify.md`.

## Interview
- **STEPS:** enumerate CORS-enabled endpoints → probe origin-reflection logic → test with credentials → confirm cross-origin read of sensitive data → rate → emit → review → verify.
- **TOOLS:** `curl`/`httpx` (Origin header fuzzing), interceptor, `puppeteer` for a real credentialed cross-origin read; `jq`.
- **GOAL:** Confirm an exploitable CORS misconfig — attacker origin reflected with `ACAC:true` over a sensitive endpoint (or sensitive data exposed to any origin) — with a cross-origin read PoC. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `cors_endpoints.json`, `origin_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/endpoints_*.txt` + `apis.json`, `auth.env`, `scope.yaml`. `refs/` = `cors_tests.md`. Chains FROM `js-analysis`; chains TO `reporting`.
- **DECOMPOSITION:** n/a (atomic). Overlaps CSRF (credentialed cross-origin) — CORS = *read*, CSRF = *write*.

## Goal
Find endpoints whose CORS policy lets an attacker origin read sensitive, credentialed responses, and
prove it with a cross-origin read. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` all `- [x]` · `review.md` PASS · every finding accepted.

## What do we want
- Endpoints returning `Access-Control-Allow-Origin` (ACAO) + whether `Access-Control-Allow-Credentials` (ACAC)
- The reflection logic: arbitrary origin? `null`? pre/post-domain/substring gaps? trusted subdomains?
- A cross-origin PoC reading sensitive data with the victim's creds

## Steps  (action · tool · output)
1. Enumerate endpoints emitting CORS headers · `httpx`/`curl` + `jq apis.json` · `cors_endpoints.json`
2. Probe origin-reflection logic (matrix of evil origins) · `refs/cors_tests.md` + `curl -H Origin` · `origin_tests.jsonl`
3. Test credentialed (`ACAC:true` + reflected origin) on SENSITIVE endpoints · interceptor · (into findings)
4. Confirm cross-origin read of sensitive data · `puppeteer` (victim session) · `poc/<id>/`
5. Rate (CVSS) + write finding · synth · `findings.json`
6. Emit report + curl · synth · `report.md`, `curl_commands.sh`
7. /REVIEW · `review.md` → `verify_completion.py`
8. /VERIFY · `verify.md`

## Tools
- **Probe:** `curl`/`httpx` with fuzzed `Origin`, interceptor
- **Confirm:** `puppeteer`/`playwright` cross-origin `fetch(..., {credentials:'include'})`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/`: `endpoints_*.txt`, `apis.json`
- `auth.env` (victim session), `scope.yaml`, `refs/cors_tests.md`

## Outputs
`cors_endpoints.json` · `origin_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** enumerate CORS endpoints + origin-reflection matrix.
- **Phase 2 (target-specific):** credentialed test on sensitive endpoints + cross-origin read PoC + rating.

## Safety
Reads only (non-destructive), but it reads sensitive data cross-origin — scope-gate; use a test
account; don't exfiltrate real user data; audit-log.
