# Data Poisoning (LLM04) — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Data supply chain mapped (training set, fine-tune, RAG index, ingestion sources)
- [ ] Approval obtained (RoE — writing a corpus/index/training set) + authorized TEST corpus + in-scope sources confirmed

## Test (scope-gated, benign, test corpus only)
- [ ] Reachable layer + target query/behaviour chosen
- [ ] Benign trigger/marker OR crafted TEST doc injected into the AUTHORIZED test corpus/index
- [ ] Benign proof — trigger→marker holds, OR TEST doc ranks #1 / grounded answer flips to the marker
- [ ] No production model/live index poisoned; no real user data used
- [ ] Injected artifacts labelled + removed / test index rebuilt (cleanup)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
