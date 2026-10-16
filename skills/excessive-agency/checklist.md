# Excessive Agency (LLM06) — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Tools + capabilities ingested from llm_context.json
- [ ] Approval obtained (RoE — LLM performs real actions)

## Abuse (scope-gated, benign)
- [ ] Tool params enumerated
- [ ] SSRF via tool (OOB / internal reach)
- [ ] Tool-arg injection (SQL / shell / path — benign markers)
- [ ] Tool chaining (indirect injection → action in another tool)
- [ ] Unauthorized action confirmed (OOB / benign effect)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (prompt + tool action + OOB evidence)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes  [empty callbacks.jsonl is a valid liveness PASS]
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
