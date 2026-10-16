# In-Band SQLi — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] In-band points ingested from sqli_context.json
- [ ] Approval obtained (RoE — data access)

## Confirm (read-only)
- [ ] Query context broken out
- [ ] Injection confirmed via error or union (benign marker: version())
- [ ] Column count/types mapped (union)
- [ ] MINIMAL proof extracted (db name/version/one benign row — no PII)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (request + extracted marker)
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
