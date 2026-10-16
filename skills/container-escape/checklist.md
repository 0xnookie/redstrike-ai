# Container Escape — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Foothold
- [ ] Container confirmed (/.dockerenv, cgroups) + in-scope host
- [ ] Approval obtained (RoE — post-exploitation)

## Enumerate
- [ ] Capabilities (amicontained / capsh --print)
- [ ] Mounts (host paths, docker.sock, /dev)
- [ ] Privileged? / cap_sys_admin? / exposed devices?

## Escape (scope-gated, benign)
- [ ] Escape vector identified
- [ ] Escaped to host BENIGNLY
- [ ] Host access proven (host marker read / host-namespace id)
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
