# Subdomain Takeover — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Enumerate
- [ ] Subdomains enumerated
- [ ] DNS records resolved (CNAME / A / NS)

## Identify
- [ ] Dangling pointers flagged (third-party target, no live resource)
- [ ] Service fingerprinted
- [ ] Unclaimed-state signature matched

## Confirm
- [ ] Claimability confirmed benignly (claim page / registration possible)
- [ ] Hostile claim ONLY if explicitly authorized (else documented, stopped)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (fingerprint + claimability evidence)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
