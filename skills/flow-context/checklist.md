# Flow Context — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Identities

- [ ] ≥2 identities loaded from auth.env (roles noted; +admin if available)

## Model

- [ ] States/pages mapped (URL + reachable_by, crawled as each identity)
- [ ] Actions enumerated per state (method/route/handler; state_change / single_use / allowed_roles)
- [ ] Transitions modeled (from → to via action; guard + guard_kind + enforced_by)
- [ ] Invariants extracted (statement + kind + break_impact + route)
  - [ ] each invariant routed to its executor (business-logic / race-condition / auth-bypass / idor / privesc)
- [ ] Multi-step workflows named (ordered steps; enforced_order)

## Emit

- [ ] flow_context.json validates against _contract/flow_context.schema.json
- [ ] summary.md
- [ ] /REVIEW SKILL passes
