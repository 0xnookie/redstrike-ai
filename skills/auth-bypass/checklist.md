# Authentication Bypass — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Auth flows + session mechanism ingested from auth_context.json
- [ ] Approval obtained (RoE); test account prepared

## Test (scope-gated, no real brute-force)
- [ ] Forced browsing past login
- [ ] Response/flag tampering (client-side gates)
- [ ] 2FA/MFA step skip
- [ ] Session fixation
- [ ] Password-reset weaknesses (predictable token / reuse / no expiry)
- [ ] Authed/privileged state reached without valid auth — confirmed
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
