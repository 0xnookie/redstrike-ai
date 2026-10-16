# LDAP Injection — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Login/search params + LDAP backend fingerprinted
- [ ] Approval obtained (RoE)

## Inject (scope-gated, benign)
- [ ] Auth-bypass filter injection ( * , *)(uid=*))(|(uid=* , admin)(&) )
- [ ] Wildcard enumeration ( * )
- [ ] Blind boolean (attribute presence)
- [ ] Confirmed (auth bypass / enumeration) benignly
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
