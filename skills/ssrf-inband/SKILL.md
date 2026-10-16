# In-Band SSRF Agent

> Variant of the SSRF family (siblings: `ssrf-blind`, `ssrf-cloud`). Consumes `ssrf_context.json`
> fetch sinks with `reflects_response: true` / `variant_hint: inband`.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval** (reaching internal
> resources). Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest in-band sinks → point at an in-scope internal/unauthorized target → read the reflected response (or diff status/length) → escalate (allowlist bypass, redirect, protocol) → capture → rate → emit → review → verify.
- **TOOLS:** interceptor, `curl`, `ssrf-context/refs/ssrf_payloads.md`; response-diffing.
- **GOAL:** Confirm SSRF where the server fetches an attacker-chosen internal/unauthorized target AND the response (or an observable differential) comes back in-band, proving internal access. Done = checklist `- [x]`, review passes, findings accepted + **approved**.
- **OUTPUT:** `ssrf_targets.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `ssrf_context.json` (inband sinks + internal_targets) + `scope.yaml`. `refs/` = the feeder's `ssrf-context/refs/`. Chains FROM `ssrf-context`; chains TO `reporting`.
- **DECOMPOSITION:** this IS the in-band variant.

## Goal
Prove internal access via a URL-fetch sink whose response is observable in-band. Emit `findings.json`
(`_contract/finding.schema.json`). DONE = `checklist.md` `- [x]` · `review.md` PASS · findings accepted.

## What do we want
- Which in-scope internal targets are reachable (metadata deferred to `ssrf-cloud`)
- The in-band evidence (reflected body / status / length differential) proving the fetch landed
- The bypass used (allowlist, redirect, protocol) + impact (internal read, port scan)

## Steps  (action · tool · output)
1. Ingest in-band sinks + internal targets from `ssrf_context.json` · `jq` · `ssrf_targets.jsonl`
2. Point each sink at an in-scope internal/unauthorized target · `curl`/interceptor · (into tests)
3. Read reflected response or diff status/length to confirm reach · response-diff · `ssrf_targets.jsonl`
4. Escalate (allowlist bypass / redirect / protocol) as needed · `ssrf-context/refs/ssrf_payloads.md` · `ssrf_targets.jsonl`
5. Capture PoC (request + reflected internal response) · interceptor · `poc/<id>/`
6. Rate (CVSS) + write finding · synth · `findings.json`
7. Emit report + curl · synth · `report.md`, `curl_commands.sh`
8. /REVIEW · `review.md` · 9. /VERIFY · `verify.md`

## Tools
- interceptor (Caido/mitmproxy), `curl`, response-diffing; `ssrf-context/refs/ssrf_payloads.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `ssrf_context.json` (inband sinks, `internal_targets`), `scope.yaml`

## Outputs
`ssrf_targets.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** ingest + confirm internal reach (in-scope) with in-band evidence.
- **Phase 2 (target-specific):** bypass escalation + impact + rating (approval-gated).

## Safety
Reaching internal resources is sensitive — **approval-gated**; stay within in-scope internal ranges
(`scope.yaml`); read-only (don't pivot/modify internal services); don't port-scan beyond confirming a
service; audit-log. Cloud metadata is out of scope here → `ssrf-cloud`.
