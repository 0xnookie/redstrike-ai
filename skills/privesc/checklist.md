# Privilege Escalation — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Role matrix + identities ingested from authz_context.json
- [ ] Approval obtained (RoE — admin actions)
- [ ] Low-priv TEST account prepared

## Test (scope-gated)
- [ ] Higher-role endpoints invoked as low-priv A
- [ ] Privileged action execution confirmed (state change / admin data)
- [ ] Forced-browsing (hidden admin paths) tested
- [ ] Method / role-param tampering tested
- [ ] Impact assessed + CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (A performs admin-only action)
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
