# AD ADCS — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] ADCS templates + ESC flags ingested from ad_context.json
- [ ] Approval obtained (RoE — high-impact AD)

## Abuse (scope-gated, test principal, revoke after)
- [ ] ESC misconfig confirmed (ESC1-8)
- [ ] Cert issued for a TEST privileged principal (or ESC8 relay)
- [ ] Authenticated with the cert (PKINIT) as the test principal
- [ ] Access confirmed; cert REVOKED (cleanup.md)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding
- [ ] cleanup.md
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
