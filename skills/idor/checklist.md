# IDOR — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Object refs + ≥2 identities ingested from authz_context.json
- [ ] Two TEST accounts/resources prepared (A, B — both yours)

## Test (scope-gated, test accounts)
- [ ] As A, requested B's object id
- [ ] Cross-owner access confirmed (B's data returned / resource modified)
- [ ] Id enumeration tested (sequential)
- [ ] Mass-assignment tested (owner_id / role / is_admin / verified / balance)
- [ ] Impact assessed + CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (A session + B id → B data)
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
