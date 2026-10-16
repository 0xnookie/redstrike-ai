# Command Injection Agent

> Variant of the injection family (siblings: `ssti`, `deserialization`). Consumes `injection_context.json`
> points with `sink_type: os_command` / `variant_hint: command-injection`.
> ACTIVE, RCE-class, HIGH-RISK, findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest command sinks → confirm execution BENIGNLY (OOB callback / `sleep` timing) → identify OS + context (direct/argument) → (approval) prove impact benignly → rate → emit → review → verify.
- **TOOLS:** interceptor, OOB (`interactsh`), `injection-context/refs/injection_payloads.md`, timing.
- **GOAL:** Confirm OS command injection via a BENIGN proof of execution (OOB or timing) — never a destructive command. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `command_tests.jsonl`, `callbacks.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `injection_context.json` (command sinks) + `scope.yaml` (`oob.collaborator`). `refs/` = `injection-context/refs/`. Chains FROM `injection-context`; chains TO `reporting`.
- **DECOMPOSITION:** this IS the command-injection variant.

## Goal
Prove command execution benignly (OOB/timing). Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · findings accepted.

## Steps  (action · tool · output)
1. Ingest command sinks · `jq injection_context.json` · (into tests)
2. Confirm execution benignly: OOB (`;curl http://OOB/`) or timing (`;sleep 5`) · interceptor + OOB · `command_tests.jsonl`
3. Correlate OOB callback (token → sink) · OOB poller · `callbacks.jsonl`
4. Identify OS + injection context (direct / within an argument / blind) · refs · `command_tests.jsonl`
5. (Approval) prove impact benignly (e.g. `whoami` to OOB) · refs · `poc/<id>/`
6. Rate (CVSS) + write finding · synth · `findings.json`
7. Emit report + curl · synth · `report.md`, `curl_commands.sh`
8. /REVIEW · `review.md` · 9. /VERIFY · `verify.md`

## Tools
- interceptor, OOB (`interactsh-client` / Collaborator), timing, `injection-context/refs/injection_payloads.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `injection_context.json` (command sinks), `scope.yaml` (`oob.collaborator`)

## Outputs
`command_tests.jsonl` · `callbacks.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** benign execution confirmation (OOB / timing).
- **Phase 2 (target-specific):** OS/context identification + benign impact proof + rating (approval-gated).

## Safety
RCE is maximum blast radius — **approval-gated**; confirm with BENIGN commands only (`sleep`, a curl
to YOUR OOB host, `whoami` exfil'd to OOB) — **never** destructive, no reverse shells, no touching
files/processes. Keep it minimal; scope-gate; rate-limit; audit-log; honor the kill switch.
