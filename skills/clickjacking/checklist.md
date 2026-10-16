# Clickjacking — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Enumerate
- [ ] Sensitive state-changing UI actions identified

## Defenses
- [ ] Framing matrix per page
  - [ ] X-Frame-Options present?
  - [ ] CSP frame-ancestors present?
  - [ ] bypassable (missing on the sensitive route, misconfig)?

## Exploit
- [ ] Framing PoC built (iframe + overlay/decoy)
- [ ] Page confirmed frameable + sensitive action reachable through frame
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (poc.html + evidence)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
