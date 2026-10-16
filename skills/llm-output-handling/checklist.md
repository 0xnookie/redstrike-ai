# LLM Output Handling (LLM05) — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Output sinks ingested from llm_context.json

## Test (scope-gated, benign)
- [ ] Model driven to emit a sink-appropriate payload
- [ ] Downstream sink fired (XSS exec / query inject / OOB fetch / code exec)
- [ ] Downstream proof handed to the web agent gauntlet (xss/sqli/ssrf/cmdi)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (LLM output + downstream execution evidence)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
