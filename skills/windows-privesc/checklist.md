# Windows Privesc — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Foothold
- [ ] In-scope host + current user + privileges confirmed (whoami /all)
- [ ] Approval obtained (RoE — post-exploitation)

## Enumerate
- [ ] Automated (winPEAS/PowerUp) + manual enumeration
  - [ ] services (unquoted path / weak perms / writable binary)
  - [ ] token privileges (SeImpersonate / SeBackup / SeDebug)
  - [ ] AlwaysInstallElevated
  - [ ] autoruns / scheduled tasks
  - [ ] DLL hijack paths
  - [ ] saved creds (cmdkey / registry / unattend / web.config)

## Exploit (scope-gated, benign)
- [ ] Vector(s) identified
- [ ] Lowest-risk vector exploited to SYSTEM/admin BENIGNLY
- [ ] SYSTEM confirmed (whoami = nt authority\system) with a benign command
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
