# In-Band XXE Agent

> Variant of the XXE family (sibling: `xxe-blind`). Consumes `xxe_context.json` sinks with
> `error_reflects: true` / `variant_hint: inband`.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval** (file read / SSRF). Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest in-band sinks → external entity for a benign file read (or SSRF to in-scope internal) → read the reflected content (direct or error-based) → rate → emit → review → verify.
- **TOOLS:** interceptor, `xxe-context/refs/xxe_payloads.md`.
- **GOAL:** Confirm XXE where an external entity is resolved AND its content is reflected in-band (benign file read / internal fetch). Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `xxe_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `xxe_context.json` (inband sinks) + `scope.yaml`. `refs/` = `xxe-context/refs/`. Chains FROM `xxe-context`; chains TO `reporting` (SSRF-via-XXE → `ssrf-cloud`).
- **DECOMPOSITION:** this IS the in-band variant.

## Goal
Prove in-band XXE (benign file read or internal fetch reflected). Emit `findings.json`
(`_contract/finding.schema.json`). DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## Steps  (action · tool · output)
1. Ingest in-band sinks · `jq xxe_context.json` · (into tests)
2. External entity → benign file (`file:///etc/hostname`) or in-scope internal URL · interceptor · `xxe_tests.jsonl`
3. Read reflected content (direct node or error-based) · interceptor · `xxe_tests.jsonl`
4. Capture PoC (payload + reflected file/internal content) · interceptor · `poc/<id>/`
5. Rate (CVSS) + write finding · synth · `findings.json`
6. Emit report + curl · synth · `report.md`, `curl_commands.sh`
7. /REVIEW · `review.md` · 8. /VERIFY · `verify.md`

## Tools
- interceptor, `xxe-context/refs/xxe_payloads.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `xxe_context.json` (inband sinks), `scope.yaml`

## Outputs
`xxe_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** external-entity benign file read / internal fetch with in-band reflection.
- **Phase 2 (target-specific):** error-based extraction + SSRF-via-XXE + rating (approval-gated).

## Safety
Benign proof — prefer `/etc/hostname` over sensitive files; read only what proves the issue; **no DoS**
(no entity expansion); SSRF-via-XXE stays in scope (hand cloud-metadata to `ssrf-cloud`). Approval-gated;
scope-gate; audit-log.
