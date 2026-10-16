# HTTP Request Smuggling — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Fingerprint
- [ ] Front-end / CDN identified
- [ ] Back-end identified
- [ ] Approval obtained before active confirmation (RoE)

## Probe (safe)
- [ ] Timing-based detection run
  - [ ] CL.TE
  - [ ] TE.CL
  - [ ] TE.TE
  - [ ] CL.CL
  - [ ] H2.CL / H2.TE downgrade
- [ ] Desync confirmed via SELF-canary (own follow-up request only)

## Assess
- [ ] Impact path described (cache / auth bypass / cred capture) — NOT weaponized vs users
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (safe PoC)
- [ ] cleanup.md (no persistent poison left)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
