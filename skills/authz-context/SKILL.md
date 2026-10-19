# AuthZ Context (shared feeder)

> RECON / context feeder for the access-control family (variants: `idor`, `privesc`).
> Needs MULTIPLE identities (≥2 accounts; +admin for vertical). Lightly active → honors
> `_contract/roe-gate.md`. Emits NO findings → `review.md` only. Output: `authz_context.json`
> (schema `_contract/authz_context.schema.json`).

## Interview
- **STEPS:** load identities → enumerate object references (ids in URLs/bodies) → build the role→endpoint matrix (crawl as each identity) → identify mass-assignable params → route → emit → review.
- **TOOLS:** interceptor with multi-session (`auth.env`), `jq` over `js-analysis`, request-diff across identities.
- **GOAL:** Build the authorization map — object references, the identity/role × endpoint matrix, and mass-assignable params — into `authz_context.json`, so `idor` and `privesc` fan out from one analysis. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `objects.json`, `role_matrix.json`, `mass_assign.json`, `authz_context.json`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/out/<site>/findings/{endpoints,params,apis}.jsonl` + `auth.env` (**≥2 identities + roles**) + `scope.yaml`. Chains FROM `js-analysis`; chains TO `idor`, `privesc`.
- **DECOMPOSITION:** n/a (feeder).

## Goal
Produce the shared authorization context: object refs + role/endpoint matrix + mass-assign candidates.
DONE = `checklist.md` `- [x]` · `review.md` PASS (`authz_context.json` validates against the schema).

## What do we want
- Object references: where a request `id` selects a resource (and id type: sequential/uuid/hashid)
- The matrix: which identity/role can reach which endpoint (observed, as each account)
- Mass-assignable params (fields the client can send that map to privileged attributes)

## Steps  (action · tool · output)
1. Load identities from `auth.env` (≥2; +admin) · read · (into context)
2. Enumerate object references + id types · `jq`/`grep` + crawl · `objects.json`
3. Build role→endpoint matrix (crawl each endpoint as each identity; record who reaches what) · multi-session interceptor · `role_matrix.json`
4. Identify mass-assignable params (compare client-settable vs server-managed fields) · request-diff · `mass_assign.json`
5. Consolidate + validate vs schema · synth · `authz_context.json`
6. Emit summary · synth · `summary.md`
7. /REVIEW SKILL · `review.md`

## Tools
- multi-session interceptor (Caido/mitmproxy with 2+ profiles), `jq`/`grep` over `js-analysis`, request-diff
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/out/<site>/findings/`: `endpoints.jsonl`, `params.jsonl`, `apis.jsonl`
- `auth.env`: **≥2 identities + roles** (attacker low-priv + victim; +admin for vertical)
- `scope.yaml`

## Outputs
`objects.json` · `role_matrix.json` · `mass_assign.json` · `authz_context.json` · `summary.md` · `logs/`

## Phases
- **Phase 1 (generic):** identity load + object-reference enumeration.
- **Phase 2 (target-specific):** role matrix + mass-assign discovery + consolidation.

## Safety
Enumeration/crawl only (no cross-account access yet — that's the variants, with care). Use TEST
accounts; scope-gate; audit-log. Don't access another account's data during mapping.
