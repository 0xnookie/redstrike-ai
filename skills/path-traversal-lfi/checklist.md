# Path Traversal / LFI — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Read/include sinks ingested from file_context.json
- [ ] Approval obtained (RoE)

## Confirm (benign)
- [ ] Traversed to a benign marker outside base dir (encodings/bypasses)
- [ ] Marker's real content confirmed returned
- [ ] (Include) LFI wrappers / log-poison → benign OOB RCE — if approved
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (payload + returned content)
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
