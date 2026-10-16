# HTTP Parameter Pollution — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Params mapped + stack fingerprinted (parser precedence)

## Test (scope-gated, benign)
- [ ] Duplicates injected per source (URL / body / JSON / cookie / header)
- [ ] Array notation + cloaking variants tried
- [ ] Precedence determined per layer (gateway vs backend)
- [ ] A security decision flipped (authz / identity / value / filter smuggle) on test identities
- [ ] Confirmed benignly
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
