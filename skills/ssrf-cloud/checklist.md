# Cloud-Metadata SSRF — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Cloud-capable sinks ingested; provider detected
- [ ] Approval obtained (RoE — metadata creds)

## Reach (scope-gated)
- [ ] Metadata endpoint reached via the sink
  - [ ] IMDSv2 token / required header handled
- [ ] Credentials / token retrieved (stored REDACTED)
- [ ] Cred scope assessed (benign identity check)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid; secrets redacted)
- [ ] poc/ per finding (request + redacted cred evidence)
- [ ] report.md (incl. IMDSv2/block mitigations)
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
