# AuthZ Context — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Identities
- [ ] ≥2 identities loaded from auth.env (roles noted; +admin if available)

## Map
- [ ] Object references enumerated (id param + id type + owner-scoped?)
- [ ] Role → endpoint matrix built (crawled as each identity)
  - [ ] who reaches which endpoint recorded
- [ ] Mass-assignable params identified (client-settable vs server-managed)

## Emit
- [ ] authz_context.json validates against _contract/authz_context.schema.json
- [ ] summary.md
- [ ] /REVIEW SKILL passes
