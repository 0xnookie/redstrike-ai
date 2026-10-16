# CSRF — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Enumerate
- [ ] State-changing requests enumerated (POST/PUT/PATCH/DELETE + sensitive GET)
- [ ] Auth model identified (cookie vs Authorization header)

## Defenses
- [ ] Per-request defense matrix
  - [ ] anti-CSRF token present?
  - [ ] token actually validated? (replay/removal tested)
  - [ ] SameSite cookie attribute (None/Lax/Strict)
  - [ ] custom-header requirement / non-simple content-type
  - [ ] origin / referer check

## Exploit (scope-gated, test account)
- [ ] Gap classified per request
- [ ] Cross-origin PoC crafted
- [ ] Change confirmed firing cross-origin with victim creds
- [ ] Impact assessed + CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (poc.html + evidence)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
