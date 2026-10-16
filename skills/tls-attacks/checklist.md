# TLS/SSL Attacks — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] TLS endpoints + STARTTLS services enumerated (in-scope host:port)
- [ ] Approval obtained (RoE — active vuln probes) + in-scope target confirmed

## Test (scope-gated, read-only scan + benign active checks)
- [ ] Protocols + ciphersuites scanned (testssl.sh / sslscan / sslyze / nmap)
- [ ] Weak config flagged (SSLv3/TLS1.0-1.1, RC4/EXPORT/DES/NULL, weak DH/keys)
- [ ] Certificate inspected (expiry, hostname/SAN, chain/trust, self-signed)
- [ ] Named issues checked (Heartbleed/POODLE/ROBOT/BEAST/CCS/Raccoon) — benign, controlled
- [ ] STARTTLS stripping + missing/weak HSTS checked
- [ ] One concrete weakness confirmed benignly (scanner evidence / controlled check)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid; any over-read bytes redacted)
- [ ] poc/ per finding (scanner output / controlled-check evidence)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
