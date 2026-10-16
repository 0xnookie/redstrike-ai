# Insecure Deserialization Agent

> Variant of the injection family (siblings: `ssti`, `command-injection`). Consumes `injection_context.json`
> points with `sink_type: deserialize` / `variant_hint: deserialization`.
> ACTIVE, RCE-class, HIGH-RISK, findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest deserialize sinks → identify format (java/php/python/.net/node) → confirm the sink deserializes attacker data with a BENIGN gadget (URLDNS-style OOB, no code exec) → assess gadget-chain feasibility → (approval) benign RCE proof via OOB → rate → emit → review → verify.
- **TOOLS:** interceptor, OOB, `ysoserial`/`ysoserial.net`/`phpggc` (URLDNS/benign gadgets), `injection-context/refs/injection_payloads.md`.
- **GOAL:** Confirm insecure deserialization — the sink deserializes attacker-controlled data — via a BENIGN OOB gadget, and assess RCE feasibility. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `deser_tests.jsonl`, `callbacks.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `injection_context.json` (deserialize sinks) + `scope.yaml` (`oob.collaborator`). `refs/` = `injection-context/refs/`. Chains FROM `injection-context`; chains TO `reporting`.
- **DECOMPOSITION:** this IS the deserialization variant.

## Goal
Prove the sink deserializes attacker data (benign OOB gadget) + assess RCE feasibility. Emit
`findings.json` (`_contract/finding.schema.json`). DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## Steps  (action · tool · output)
1. Ingest deserialize sinks + identify format · `jq` + markers · (into tests)
2. Send a BENIGN gadget (URLDNS / DNS-only) that only triggers an OOB callback · `ysoserial`/`phpggc` + OOB · `deser_tests.jsonl`
3. Correlate callback (proves deserialization) · OOB poller · `callbacks.jsonl`
4. Assess gadget-chain feasibility (available libs from `libraries.json`) · refs · `deser_tests.jsonl`
5. (Approval) benign RCE proof via an OOB command gadget · refs · `poc/<id>/`
6. Rate (CVSS) + write finding · synth · `findings.json`
7. Emit report + curl · synth · `report.md`, `curl_commands.sh`
8. /REVIEW · `review.md` · 9. /VERIFY · `verify.md`

## Tools
- interceptor, OOB, `ysoserial`/`ysoserial.net`/`phpggc` (URLDNS/benign gadgets), `injection-context/refs/injection_payloads.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `injection_context.json` (deserialize sinks), `js-analysis/libraries.json` (gadget libs), `scope.yaml`

## Outputs
`deser_tests.jsonl` · `callbacks.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** format ID + benign deserialization confirmation (URLDNS/OOB).
- **Phase 2 (target-specific):** gadget-chain feasibility + benign RCE proof via OOB (approval-gated).

## Safety
Gadget chains can be destructive — use **URLDNS / DNS-only benign gadgets** to confirm deserialization;
real RCE gadgets are **approval-gated** and proven BENIGNLY (OOB only). Never run a gadget that writes
files, spawns shells, or persists. Scope-gate; audit-log; kill switch.
