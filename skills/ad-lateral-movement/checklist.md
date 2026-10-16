# AD Lateral Movement — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Recovered creds/hashes/tickets + in-scope targets ingested
- [ ] Approval obtained (RoE — high-impact AD)

## Move (scope-gated, benign exec, in-scope hosts)
- [ ] PtH / PtT / overpass-the-hash to an in-scope host
- [ ] (Approval) NTLM relay + coercion
- [ ] Benign command run (whoami/hostname) to confirm access
- [ ] Reach mapped (hosts + privilege); artifacts removed (cleanup.md)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding
- [ ] cleanup.md
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
