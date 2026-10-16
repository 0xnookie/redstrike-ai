# Command Injection — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Command sinks ingested from injection_context.json
- [ ] Approval obtained (RoE — RCE class)

## Confirm (benign)
- [ ] Execution confirmed via OOB (;curl http://OOB/) or timing (;sleep 5)
- [ ] OOB callback correlated (token → sink)
- [ ] OS + injection context identified (direct / argument / blind)
- [ ] Benign impact proof (e.g. whoami → OOB) — if approved
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (payload + callback/timing evidence)
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes  [empty callbacks.jsonl is a valid liveness PASS]
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
