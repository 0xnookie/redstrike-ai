# Secrets Validation — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Candidates ingested (js-analysis/out/<site>/findings/secrets.jsonl + other sources)
- [ ] Deduped
- [ ] Classified by type

## Filter
- [ ] Obvious noise filtered (example/test/placeholder, low entropy)

## Validate (scope-gated, benign)
- [ ] Liveness validated per candidate (minimal read-only probe where authorized)
  - [ ] active / revoked / placeholder recorded
  - [ ] secrets stored REDACTED (no full secret in artifacts)
- [ ] Scope/impact assessed per live secret
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
