# Sensitive Disclosure Agent  (OWASP LLM02 / LLM07 / LLM08)

> Variant of the AI/LLM family (siblings: `prompt-injection`, `excessive-agency`, `llm-output-handling`).
> System-prompt leakage + sensitive info disclosure + cross-tenant leakage + RAG/embedding extraction.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md`. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest data sources → extract the system prompt → probe cross-conversation/tenant leakage → RAG source extraction → training-data memorization → confirm extraction (corroborated, benign) → rate → emit → review → verify.
- **TOOLS:** interceptor, `garak`/`PyRIT` (leakage probes), `llm-context/refs/llm_testing_guide.md`.
- **GOAL:** Confirm sensitive disclosure — the app leaks its system prompt, another user's/tenant's data, or RAG/KB contents — corroborated, not a hallucination. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `disclosure_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = `llm_context.json` (`data_sources`) + `scope.yaml`. `refs/` = `llm-context/refs/`. Chains FROM `llm-context` (+ `prompt-injection` as a delivery vector); chains TO `reporting`.
- **DECOMPOSITION:** this IS the disclosure variant (LLM02/07/08).

## Goal
Prove sensitive disclosure, corroborated + benign. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## What do we want
- The system prompt (LLM07) — extracted + corroborated it's the REAL one
- Sensitive info the model shouldn't reveal (LLM02) — keys/PII/internal config in its context
- Cross-conversation/tenant leakage — another user's prompt/memory/data
- RAG/embedding extraction (LLM08) — which docs retrieved, raw chunks, KB enumeration

## Steps  (action · tool · output)
1. Ingest data sources + guardrails · `jq llm_context.json` · (into tests)
2. System-prompt extraction (direct / diagnostic framing / completion bait / incremental / tag-aware) · refs · `disclosure_tests.jsonl`
3. Cross-conversation/tenant leakage probe (another session's data) · interceptor · `disclosure_tests.jsonl`
4. RAG source extraction (which docs? raw chunks? enumerate KB) · refs · `disclosure_tests.jsonl`
5. Training-data memorization (divergence/completion) — benign marker · refs · `disclosure_tests.jsonl`
6. Confirm extraction is REAL (corroborate against known-good, not hallucinated) · synth · `poc/<id>/`
7. Rate (CVSS) + write finding · synth · `findings.json`
8. Emit report · synth · `report.md`
9. /REVIEW · `review.md` · 10. /VERIFY · `verify.md`

## Tools
- interceptor, `garak`/`PyRIT`, `llm-context/refs/llm_testing_guide.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `llm_context.json` (`data_sources`), `scope.yaml`

## Outputs
`disclosure_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** system-prompt extraction + corroboration.
- **Phase 2 (target-specific):** cross-tenant + RAG + training-data extraction + rating.

## Safety
Corroborate extractions (a model will happily HALLUCINATE a plausible system prompt) — only report what's
verifiably real. For cross-tenant, use tester-controlled second accounts; **never** exfiltrate real users'
data — a reproduced leak of a tester-planted marked record is the proof. Rate-limit; scope; audit-log.
