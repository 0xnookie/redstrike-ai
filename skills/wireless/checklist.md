# Wireless Assessment — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] In-scope SSIDs/BSSIDs/clients surveyed + RF scope confirmed
- [ ] Approval obtained (RoE — RF assessment) + deauth-against-prod explicitly forbidden

## Test (scope-gated, benign, test network/client)
- [ ] WPA2-PSK handshake captured (passive / approved test client) + offline-cracked
- [ ] WPS pixie-dust tested on an authorized AP (if WPS enabled)
- [ ] WPA3-SAE transition/downgrade assessed + SAE weaknesses noted
- [ ] Evil-twin / captive portal stood up for a TEST client (benign test credential) — torn down after
- [ ] WPA-Enterprise EAP challenge/response captured (benign test identity) + offline-cracked
- [ ] One issue confirmed benignly — no deauth against production
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid, PSK/PIN/creds redacted)
- [ ] poc/ per finding
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
