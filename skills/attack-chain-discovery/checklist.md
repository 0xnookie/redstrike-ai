# Attack Chain Discovery — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] All ACCEPTED findings ingested (review.verdict == accepted)

## Compose
- [ ] Each finding modeled as a primitive (capability + preconditions + outputs)
- [ ] Chains composed (output→precondition match; ≥2 steps)
- [ ] Feasibility assessed (demonstrated / plausible / theoretical)
- [ ] Combined impact / CVSS rated
- [ ] (Approval) a high-value chain demonstrated BENIGNLY end-to-end

## Emit
- [ ] chains.json validates against _contract/attack_chain.schema.json
- [ ] findings.json (composite chain findings; schema-valid)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every chain accepted or rejected with reason
