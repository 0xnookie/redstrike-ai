# Linux Privesc — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Foothold
- [ ] In-scope host + current user confirmed
- [ ] Approval obtained (RoE — post-exploitation)

## Enumerate
- [ ] Automated (linpeas) + manual enumeration
  - [ ] SUID/SGID
  - [ ] sudo -l
  - [ ] cron / timers
  - [ ] capabilities
  - [ ] kernel version
  - [ ] writable files/services + PATH
  - [ ] group memberships (docker/lxd/disk) + creds

## Exploit (scope-gated, benign)
- [ ] Vector(s) identified
- [ ] Lowest-risk vector exploited to root BENIGNLY
- [ ] Root confirmed (id = uid=0) with a benign command
- [ ] Anything created reverted (cleanup.md)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding
- [ ] cleanup.md
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
