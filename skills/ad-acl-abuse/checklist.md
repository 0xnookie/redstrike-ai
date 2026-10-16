# AD ACL Abuse — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] ACL edges + foothold ingested from ad_context.json
- [ ] Approval obtained (RoE — high-impact AD)

## Abuse (scope-gated, test targets, ALWAYS revert)
- [ ] Edge exercised on a TEST target
  - [ ] ForceChangePassword (reset test user)
  - [ ] AddKeyCredentialLink → shadow cred → NT hash
  - [ ] WriteDacl/GenericAll → grant then revert
  - [ ] AddMember → add test account then remove
- [ ] (Approval) DCSync a SINGLE test account (not the domain)
- [ ] Abuse confirmed; ALL changes reverted (cleanup.md)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding
- [ ] cleanup.md
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
