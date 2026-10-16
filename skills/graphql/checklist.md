# GraphQL — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] GraphQL schema/ops ingested from api_context.json
- [ ] ≥2 identities available

## Test (scope-gated, NO DoS)
- [ ] Introspection check (__schema exposed?)
- [ ] Field-level authz (low-priv queries a restricted field)
- [ ] Node IDOR (node(id:) / global ids to another owner)
- [ ] Arg injection markers (hand to injection agents)
- [ ] DoS feasibility ASSESSED + reported (NOT executed)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
