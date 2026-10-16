# Prompt Injection (LLM01) — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Injection points + guardrails ingested from llm_context.json
- [ ] Benign canary planted/identified (marker the model must not reveal, or OOB beacon)

## Inject (scope-gated, benign)
- [ ] Direct injection (persona / instruction override / context reset / multi-turn)
- [ ] Role injection (client-supplied system/assistant/tool roles; mixed-role arrays)
- [ ] Indirect injection (poisoned doc/RAG/web the model ingests)
- [ ] Output-filter bypass (encoding / semantic) if blocked
- [ ] Subversion confirmed (canary revealed / injected instruction executed)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (prompt + subverted response)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
