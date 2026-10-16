# Auth Context (shared feeder)

> RECON / context feeder for the auth family (variants: `auth-bypass`, `jwt`, `oauth`).
> Lightly active → honors `_contract/roe-gate.md`. Emits NO findings → `review.md` only.
> Output: `auth_context.json` (schema `_contract/auth_context.schema.json`).

## Interview
- **STEPS:** map auth surfaces (login/session/token/reset/MFA/OAuth) → characterize session mechanism (cookie flags, JWT?, fixation, logout) → enumerate flows → fingerprint OAuth/OIDC → route → emit → review.
- **TOOLS:** interceptor, `jq` over `js-analysis`, JWT decoder; `refs/auth_techniques.md`.
- **GOAL:** Map the auth attack surface — session mechanism, flows, token type, OAuth config — into `auth_context.json`. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `surfaces.json`, `session.json`, `auth_context.json`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/{endpoints_*.txt,apis.json}` + `auth.env` (a session to inspect) + `scope.yaml`. `refs/` = `auth_techniques.md`. Chains FROM `js-analysis`; chains TO `auth-bypass`, `jwt`, `oauth`.
- **DECOMPOSITION:** n/a (feeder).

## Goal
Produce the shared auth context (session mechanism + flows + OAuth config + routing).
DONE = `checklist.md` `- [x]` · `review.md` PASS (`auth_context.json` validates against the schema).

## What do we want
- Session mechanism: cookie (flags: Secure/HttpOnly/SameSite) vs JWT (alg) vs opaque token; fixation? logout invalidation?
- Flows: login, registration, password-reset, MFA, OAuth/SSO
- OAuth/OIDC config: provider, flow (code/implicit/PKCE), `redirect_uri` param, `state` usage

## Steps  (action · tool · output)
1. Map auth surfaces/flows · `jq`/`grep` js-analysis + crawl · `surfaces.json`
2. Characterize session (inspect a token via `auth.env`; cookie flags; JWT decode) · interceptor + JWT decoder · `session.json`
3. Test fixation (does the session id change on login?) + logout invalidation (benign) · interceptor · `session.json`
4. Fingerprint OAuth/OIDC flow + `redirect_uri`/`state` · interceptor · (into context)
5. Route each flow (`variant_hint`) + consolidate + validate vs schema · synth · `auth_context.json`
6. Emit summary · synth · `summary.md`
7. /REVIEW SKILL · `review.md`

## Tools
- interceptor, `jq`/`grep` over `js-analysis`, JWT decoder (jwt_tool/jwt.io offline), `refs/auth_techniques.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/`: `endpoints_*.txt`, `apis.json`
- `auth.env` (a valid session to inspect), `scope.yaml`, `refs/auth_techniques.md`

## Outputs
`surfaces.json` · `session.json` · `auth_context.json` · `summary.md` · `logs/`

## Phases
- **Phase 1 (generic):** surface/flow mapping + session characterization.
- **Phase 2 (target-specific):** OAuth/OIDC fingerprint + routing.

## Safety
Inspection only (decode your OWN token; benign fixation/logout checks) — no credential attacks here
(variants, with care). Use a TEST account; scope-gate; audit-log.
