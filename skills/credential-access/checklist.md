# Credential Access — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Foothold
- [ ] Credential surface scoped (service / hash set / store) + in-scope
- [ ] Approval obtained (RoE — post-exploitation) + lockout/rate policy confirmed

## Test (scope-gated, benign, redact as you go)
- [ ] Online guessing attempted — rate-limited, lockout-aware, few attempts
- [ ] Hashes collected from an authorized host/store (redacted)
- [ ] Offline cracking attempted (wordlist → rules → mask)
- [ ] ONE weak/recovered credential confirmed benignly
- [ ] Collected hash files removed; secrets redacted to fingerprints (cleanup.md)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid, secrets REDACTED)
- [ ] poc/ per finding
- [ ] cleanup.md
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
