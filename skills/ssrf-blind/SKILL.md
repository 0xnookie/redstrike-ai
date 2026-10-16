# Blind SSRF Agent

> Variant of the SSRF family (siblings: `ssrf-inband`, `ssrf-cloud`). Consumes `ssrf_context.json`
> sinks with `reflects_response: false` / `variant_hint: blind`.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md`. Carries `review.md` + `verify.md`.
> Confirmation is OUT-OF-BAND (no response reflected) — like blind XSS but server-side.

## Interview
- **STEPS:** ingest blind sinks → set up OOB listener → send token-tagged fetch URLs → confirm server-side fetch via callback → probe internal reach (timing/behavioral, no reflection) → rate (conservatively) → emit → review → verify.
- **TOOLS:** OOB (`interactsh`/Collaborator), `curl`/interceptor, timing analysis; `ssrf-context/refs/`.
- **GOAL:** Confirm blind SSRF — a server-side fetch the tester cannot see in-band, proven by an attributable OOB callback from the target's egress — and probe internal reachability via timing. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `oob_config.json`, `probes.jsonl`, `callbacks.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `ssrf_context.json` (blind sinks) + `scope.yaml` (`oob.collaborator` required). `refs/` = `ssrf-context/refs/`. Chains FROM `ssrf-context`; chains TO `reporting`.
- **DECOMPOSITION:** this IS the blind variant.

## Goal
Prove a server-side fetch with no in-band reflection via an attributable OOB callback; assess internal
reachability by timing. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · findings backed by a callback, accepted.

## What do we want
- Attributable OOB callbacks from the target egress per blind sink (token → sink map)
- Internal reachability signal via timing (open vs filtered port latency) where feasible
- Honest impact (blind SSRF is often Medium unless escalated to internal interaction)

## Steps  (action · tool · output)
1. Ingest blind sinks · `jq ssrf_context.json` · (into probes)
2. Stand up OOB listener (token scheme) · `interactsh-client` · `oob_config.json`
3. Send token-tagged fetch URLs per sink · `curl`/interceptor · `probes.jsonl`
4. Correlate callbacks (token → sink, egress IP) · OOB poller · `callbacks.jsonl`
5. Probe internal reachability by timing (optional, in-scope) · timing · `probes.jsonl`
6. Rate (CVSS, conservative) + write finding · synth · `findings.json`
7. Emit report + curl · synth · `report.md`, `curl_commands.sh`
8. /REVIEW · `review.md` · 9. /VERIFY · `verify.md`

## Tools
- OOB (`interactsh-client` / Collaborator), `curl`/interceptor, timing differentials; `ssrf-context/refs/ssrf_payloads.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `ssrf_context.json` (blind sinks), `scope.yaml` (`oob.collaborator` required)

## Outputs
`oob_config.json` · `probes.jsonl` · `callbacks.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** OOB setup + token-tagged fetch probes.
- **Phase 2 (target-specific):** callback correlation + timing-based internal reachability + rating.

## Safety
Benign OOB only; timing probes must not stress internal services (scope-gated, rate-limited). No
in-band data to exfil here. Async callbacks — keep the listener up for the window. Audit-log the token map.
