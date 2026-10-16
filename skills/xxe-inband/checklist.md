# In-Band XXE — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] In-band sinks ingested from xxe_context.json
- [ ] Approval obtained (RoE — file read / SSRF)

## Confirm (benign)
- [ ] External entity → benign file (/etc/hostname) or in-scope internal URL
- [ ] Reflected content read (direct or error-based)
- [ ] SSRF-via-XXE noted (hand metadata to ssrf-cloud)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (payload + reflected content)
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
