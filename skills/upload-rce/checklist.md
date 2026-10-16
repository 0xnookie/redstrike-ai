# Upload-to-RCE — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Upload sinks ingested from file_context.json
- [ ] Approval obtained (RoE — RCE class)

## Exploit (scope-gated, benign)
- [ ] Type/validation bypass found (ext / magic bytes / content-type / double-ext / .htaccess)
- [ ] BENIGN marker-webshell uploaded (echoes marker / OOB — NOT a real shell)
- [ ] Stored path located (web-reachable + executable)
- [ ] Execution confirmed (marker returned / OOB callback)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (upload + execution evidence)
- [ ] cleanup.md (uploaded artifacts recorded + removed)
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
