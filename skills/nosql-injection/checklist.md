# NoSQL Injection — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Params + NoSQL backend fingerprinted
- [ ] Approval obtained (RoE — data access)

## Inject (scope-gated, benign)
- [ ] Operator injection in auth ($ne/$gt via JSON + PHP array bracket)
- [ ] Operator injection in queries ($gt/$regex/$in)
- [ ] Syntax injection + $where JS injection
- [ ] Blind ($where sleep / $regex boolean) — minimal, short sleeps
- [ ] Confirmed (auth bypass / differential) benignly
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
