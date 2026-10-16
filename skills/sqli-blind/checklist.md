# Blind SQLi — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Blind points ingested from sqli_context.json
- [ ] Approval obtained (RoE)

## Confirm (read-only)
- [ ] Boolean differential reproducible (1=1 vs 1=2)
- [ ] Time-based confirmed (conditional SLEEP; baseline vs delayed, repeated)
- [ ] OOB attempted where supported
- [ ] Minimal benign fact inferred (e.g. version char) as proof
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (differential/timing/OOB evidence)
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes  [empty callbacks.jsonl is a valid liveness PASS]
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
