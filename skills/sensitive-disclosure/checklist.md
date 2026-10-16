# Sensitive Disclosure (LLM02/07/08) — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Data sources + guardrails ingested from llm_context.json

## Extract (scope-gated, corroborated)
- [ ] System-prompt extraction + corroborated REAL (not hallucinated)
- [ ] Cross-conversation / tenant leakage (tester second account)
- [ ] RAG source extraction (docs / chunks / KB enumeration)
- [ ] Training-data memorization (benign marker)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (prompt + leaked-but-corroborated content)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
