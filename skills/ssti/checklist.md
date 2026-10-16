# SSTI — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Template sinks ingested from injection_context.json

## Confirm (benign)
- [ ] Server-side evaluation confirmed ( {{7*7}} -> 49 )
- [ ] Engine fingerprinted
- [ ] Benign engine proof (config/object read — NOT exec)
- [ ] Sandbox/escape assessed
- [ ] RCE escalation proven BENIGNLY via OOB/sleep (approval) — if applicable
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
