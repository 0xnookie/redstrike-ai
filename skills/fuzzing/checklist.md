# Fuzzing — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Target + input surface identified (binary/library/parser/network-API)
- [ ] Approval obtained (RoE — fuzzing may crash services) + in-scope target confirmed

## Test (scope-gated, benign, authorized instance)
- [ ] Instrumented harness built (ASAN/UBSAN + coverage) OR black-box harness ready
- [ ] Seed corpus + dictionary assembled
- [ ] Coverage-guided / structure-aware / network-API campaign run
- [ ] Crashes collected + triaged to a bug class (ASAN/UBSAN, exploitable/crashwalk)
- [ ] Crashes deduped to unique root causes
- [ ] Crashing input minimized + deterministically reproduced
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid; minimized input + sanitizer trace referenced)
- [ ] poc/ per finding (minimized repro input + trace)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
