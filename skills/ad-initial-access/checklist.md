# AD Initial Access — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Foothold
- [ ] In-scope internal network position confirmed
- [ ] Approval obtained (RoE — post-exploitation) + lockout policy read

## Test (scope-gated, benign, redact)
- [ ] Surface mapped (LLMNR/NBT-NS/mDNS, IPv6, SMB signing, pass-pol)
- [ ] Passive name-resolution capture attempted (NetNTLMv2, redacted)
- [ ] Coercion toward an in-scope listener (where applicable)
- [ ] Policy-first spraying (one password, spaced, lockout-aware)
- [ ] Anonymous enumeration (null/anon SMB/LDAP)
- [ ] ONE valid credential confirmed (offline crack / benign auth) — no lockouts
- [ ] Poisoning stopped; artifacts removed; secrets redacted (cleanup.md)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid, secrets REDACTED)
- [ ] poc/ per finding
- [ ] cleanup.md
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
