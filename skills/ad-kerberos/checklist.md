# AD Kerberos — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Flagged principals + foothold ingested from ad_context.json
- [ ] Approval obtained (RoE — high-impact AD)

## Attack (scope-gated, offline crack)
- [ ] Kerberoast (TGS) → cracked OFFLINE
- [ ] AS-REP roast → cracked OFFLINE
- [ ] Delegation abuse (unconstrained / constrained-S4U / RBCD) — demonstrated on test target
- [ ] (Approval) golden/silver ticket capability (test principal, no persistence)
- [ ] Vector confirmed; created objects recorded + removed (cleanup.md)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding
- [ ] cleanup.md
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
