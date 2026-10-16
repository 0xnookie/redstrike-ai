# Linux Privesc — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Foothold
- [ ] In-scope host + current user confirmed
- [ ] Approval obtained (RoE — post-exploitation)

## Enumerate  (READ-ONLY — see refs/enumeration.md)
- [ ] linpeas.sh delivered to target (curl|sh / attacker http.server / base64 paste) and recorded in cleanup.md
- [ ] linpeas.sh -a run from /dev/shm, teed to enum.txt (raw output kept as evidence)
- [ ] 🔴🟡 highlighted hits triaged into enum.json (vector + evidence line + section)
- [ ] pspy run a few minutes (root cron / process timing / PATH-hijack candidates)
- [ ] second opinion: lse.sh / linux-exploit-suggester (kernel+sudo+pkexec CVEs)
- [ ] manual pass confirms each candidate:
  - [ ] sudo -l (NOPASSWD, env_keep LD_PRELOAD/LD_LIBRARY_PATH)
  - [ ] SUID/SGID (+ installed-vs-GTFOBins match) and capabilities (getcap -r /)
  - [ ] cron / timers / writable services + units
  - [ ] kernel + distro version (vs suggester)
  - [ ] writable files/dirs + PATH ('.' or writable dir early)
  - [ ] group memberships (docker/lxd/disk/adm/shadow/fail2ban)
  - [ ] writable /etc/passwd or /etc/shadow
  - [ ] NFS /etc/exports no_root_squash
  - [ ] readable creds / keys / backups / history / /proc cmdline
  - [ ] container? cloud metadata? (/.dockerenv, 169.254.169.254)

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
