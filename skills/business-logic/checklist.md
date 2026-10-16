# Business Logic — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Model
- [ ] Key workflows + state machines modeled (workflow_model.md)
- [ ] Invariants/assumptions enumerated per workflow (invariants.json)
  - [ ] price/amount integrity
  - [ ] ownership / role gates
  - [ ] ordering / state transitions
  - [ ] quantity / limits / one-time use

## Abuse (scope-gated, test accounts)
- [ ] Tests designed per invariant
  - [ ] tamper (price, quantity, id)
  - [ ] reorder / skip workflow step
  - [ ] replay / reuse (coupon, token)
  - [ ] race / TOCTOU
  - [ ] negative / overflow / currency
- [ ] Tests executed (abuse_tests.jsonl)
- [ ] Invariant break confirmed WITH impact

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
