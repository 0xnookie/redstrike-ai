# SSTI Agent

> Variant of the injection family (siblings: `command-injection`, `deserialization`). Consumes
> `injection_context.json` points with `sink_type: template` / `variant_hint: ssti`.
> ACTIVE, can lead to RCE, findings-producing → imports `_contract/roe-gate.md` + **approval** for exec. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest template sinks → confirm evaluation (`{{7*7}}`→49) → fingerprint engine → benign engine-specific proof (read a config/object, NOT exec) → assess sandbox/escape → (approval) benign RCE proof via OOB → rate → emit → review → verify.
- **TOOLS:** interceptor, `injection-context/refs/injection_payloads.md`, `tplmap` (careful, confirm manually).
- **GOAL:** Confirm server-side template injection (expression evaluated server-side) and assess escalation to RCE, with BENIGN proofs. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `probes.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `injection_context.json` (template sinks) + `scope.yaml` (`oob.collaborator`). `refs/` = `injection-context/refs/`. Chains FROM `injection-context`; chains TO `reporting`.
- **DECOMPOSITION:** this IS the SSTI variant.

## Goal
Prove SSTI via server-side expression evaluation; assess RCE escalation benignly. Emit `findings.json`
(`_contract/finding.schema.json`). DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## Steps  (action · tool · output)
1. Ingest template sinks · `jq injection_context.json` · (into probes)
2. Confirm evaluation (`{{7*7}}`/`${7*7}` → 49) · interceptor · `probes.jsonl`
3. Fingerprint engine (`{{7*'7'}}` etc.) · refs · `probes.jsonl`
4. Benign engine proof (read config/object; NOT exec) · refs · `poc/<id>/`
5. Assess sandbox/escape; (approval) benign RCE proof via OOB (`sleep`/callback) · refs · `probes.jsonl`
6. Rate (CVSS) + write finding · synth · `findings.json`
7. Emit report + curl · synth · `report.md`, `curl_commands.sh`
8. /REVIEW · `review.md` · 9. /VERIFY · `verify.md`

## Tools
- interceptor, `injection-context/refs/injection_payloads.md`, `tplmap` (confirm manually)
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `injection_context.json` (template sinks), `scope.yaml` (`oob.collaborator`)

## Outputs
`probes.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** evaluation confirmation + engine fingerprint (benign math/object).
- **Phase 2 (target-specific):** sandbox/escape assessment + benign RCE proof via OOB (approval-gated).

## Safety
Confirm with arithmetic/object reads first. RCE escalation is **approval-gated** and proven BENIGNLY
(an OOB callback or `sleep`) — NEVER a destructive command. Keep payloads minimal; scope-gate; audit-log.
