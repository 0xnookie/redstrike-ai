# BOLA / BFLA — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Endpoints + ≥2 identities ingested from api_context.json
- [ ] Two TEST accounts/objects prepared (A, B — both yours)
- [ ] Approval obtained for BFLA (RoE)

## Test (scope-gated, test accounts)
- [ ] BOLA: A accessed B's object id
- [ ] BFLA: low-priv A called a privileged operation
- [ ] Excessive data exposure (returned fields vs needed)
- [ ] Mass assignment (role / isAdmin / verified)
- [ ] Impact assessed + CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
