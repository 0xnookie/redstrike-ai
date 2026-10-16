# Auth Context — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Map
- [ ] Auth surfaces/flows mapped (login, registration, reset, MFA, OAuth/SSO)

## Characterize session
- [ ] Mechanism identified (cookie / JWT / opaque)
  - [ ] cookie flags (Secure / HttpOnly / SameSite)
  - [ ] JWT? decoded (alg)
- [ ] Fixation checked (session id changes on login?)
- [ ] Logout invalidation checked

## OAuth
- [ ] OAuth/OIDC flow fingerprinted (code/implicit/PKCE; redirect_uri; state)

## Route + emit
- [ ] variant_hint per flow (auth-bypass / jwt / oauth)
- [ ] auth_context.json validates against _contract/auth_context.schema.json
- [ ] summary.md
- [ ] /REVIEW SKILL passes
