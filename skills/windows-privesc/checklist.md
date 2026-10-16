# Windows Privesc — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Foothold
- [ ] In-scope host + current user + privileges confirmed (whoami /all)
- [ ] Approval obtained (RoE — post-exploitation)

## Enumerate  (READ-ONLY — see refs/enumeration.md)
- [ ] whoami /all run first (groups + token privileges + integrity level)
- [ ] winPEAS delivered (SMB/certutil/IWR) and recorded in cleanup.md
- [ ] winPEAS run with log=enum.txt (raw output kept as evidence); AV-blocked → manual pass used
- [ ] RED highlighted hits triaged into enum.json (vector + evidence line + section)
- [ ] second opinion: PowerUp Invoke-AllChecks / Seatbelt -group=all / PrivescCheck
- [ ] WES-NG run offline vs systeminfo (patch/kernel CVEs)
- [ ] manual pass confirms each candidate:
  - [ ] token privileges (SeImpersonate/SeBackup/SeRestore/SeTakeOwnership/SeDebug)
  - [ ] services: unquoted path / weak perms (accesschk) / writable binary (icacls)
  - [ ] AlwaysInstallElevated (HKCU + HKLM both = 1)
  - [ ] scheduled tasks / autoruns (Run-As-SYSTEM + writable target)
  - [ ] DLL hijack paths
  - [ ] saved creds (cmdkey / autologon / unattend.xml / web.config / PuTTY / PS history)

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
