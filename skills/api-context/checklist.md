# API Context — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Detect
- [ ] API style detected (REST / GraphQL)
- [ ] Spec loaded (OpenAPI) or GraphQL introspected

## Map
- [ ] Endpoints/operations enumerated (+ methods)
- [ ] Object-id params mapped (BOLA surface)
- [ ] Required roles mapped (BFLA surface, ≥2 identities)
- [ ] Returned fields mapped (excessive-data surface)
- [ ] GraphQL: introspection state, queries/mutations

## Route + emit
- [ ] variant_hint per endpoint (bola-bfla / graphql)
- [ ] api_context.json validates against _contract/api_context.schema.json
- [ ] summary.md
- [ ] /REVIEW SKILL passes
