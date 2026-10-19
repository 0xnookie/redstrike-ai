# API Context (shared feeder)

> RECON / context feeder for the API family (variants: `bola-bfla`, `graphql`).
> Needs MULTIPLE identities for authz. Lightly active → honors `_contract/roe-gate.md`. Emits NO
> findings → `review.md` only. Output: `api_context.json` (schema `_contract/api_context.schema.json`).

## Interview
- **STEPS:** detect API style (REST/GraphQL) → enumerate endpoints/operations (spec, introspection) → map object params + required roles + returned fields → route → emit → review.
- **TOOLS:** interceptor, `jq` over `js-analysis/out/<site>/findings/apis.jsonl`, GraphQL introspection, `refs/api_techniques.md`.
- **GOAL:** Map the API attack surface — endpoints/operations, object-id params (BOLA), role gates (BFLA), returned fields (excessive data), GraphQL schema — into `api_context.json`. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `endpoints.json`, `graphql_schema.json`, `api_context.json`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/out/<site>/findings/{apis,endpoints}.jsonl` + OpenAPI/GraphQL spec + `auth.env` (**≥2 identities**) + `scope.yaml`. `refs/` = `api_techniques.md`. Chains FROM `js-analysis`; chains TO `bola-bfla`, `graphql`. Reuses `authz-context` concepts.
- **DECOMPOSITION:** n/a (feeder).

## Goal
Produce the shared API context (endpoints/operations + object/role surface + GraphQL schema + routing).
DONE = `checklist.md` `- [x]` · `review.md` PASS (`api_context.json` validates against the schema).

## What do we want
- API style + endpoint/operation inventory (from OpenAPI / GraphQL introspection / crawling)
- Per endpoint: object-id param (BOLA surface), required role (BFLA surface), returned fields (excessive data)
- GraphQL: introspection on? queries/mutations; nested/batched surface

## Steps  (action · tool · output)
1. Detect API style + load spec (OpenAPI/Swagger) or introspect GraphQL · interceptor · `endpoints.json`, `graphql_schema.json`
2. Enumerate endpoints/operations + methods · `jq` over `apis.jsonl` + spec · `endpoints.json`
3. Map object params, required roles (crawl as each identity), returned fields · multi-session interceptor · `endpoints.json`
4. Route each (`variant_hint`) · synth · (into context)
5. Consolidate + validate vs schema · synth · `api_context.json`
6. Emit summary · synth · `summary.md`
7. /REVIEW SKILL · `review.md`

## Tools
- interceptor, `jq` over `js-analysis/out/<site>/findings/apis.jsonl`, GraphQL introspection query, `refs/api_techniques.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/out/<site>/findings/`: `apis.jsonl`, `endpoints.jsonl`; OpenAPI/GraphQL spec if present
- `auth.env` (**≥2 identities**), `scope.yaml`, `refs/api_techniques.md`

## Outputs
`endpoints.json` · `graphql_schema.json` · `api_context.json` · `summary.md` · `logs/`

## Phases
- **Phase 1 (generic):** style detection + endpoint/operation enumeration.
- **Phase 2 (target-specific):** object/role/field mapping + routing.

## Safety
Enumeration only; GraphQL introspection is read-only; **no deep-nesting/batched DoS** queries. Use
TEST accounts; scope-gate; audit-log.
