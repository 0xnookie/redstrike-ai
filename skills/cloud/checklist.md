# Cloud Exploitation — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Provider + reachable surface identified (IMDS/SSRF, keys, public storage, exposed service)
- [ ] Approval obtained (RoE — cloud account) + in-scope account IDs confirmed

## Test (scope-gated, benign, read-only)
- [ ] Credentials obtained (SSRF→IMDS v1/v2, or given keys) — REDACTED in artifacts
- [ ] Identity confirmed (sts:GetCallerIdentity / az account show / token info)
- [ ] Permissions enumerated (read-only)
- [ ] Privesc path OR data-exposure path identified
- [ ] Benign proof (own identity + one marker read) — no bulk data, no resource changes
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid, creds redacted)
- [ ] poc/ per finding
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
