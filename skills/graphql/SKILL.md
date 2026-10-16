# GraphQL Agent

> Variant of the API family (sibling: `bola-bfla`). Consumes `api_context.json` `graphql`.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest GraphQL schema → introspection check → field-level authz tests → IDOR via `node(id:)` → injection via args → (report-only) DoS feasibility → rate → emit → review → verify.
- **TOOLS:** interceptor, introspection query, `graphw00f`/`clairvoyance` (schema), `api-context/refs/api_techniques.md`.
- **GOAL:** Confirm GraphQL-specific flaws — introspection exposure, field-authz bypass, node IDOR, arg injection — without running DoS. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `gql_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `api_context.json` (graphql schema/ops) + `auth.env` (≥2 identities) + `scope.yaml`. `refs/` = `api-context/refs/`. Chains FROM `api-context`; injection via args ↔ `injection-*`/`sqli-*`. Chains TO `reporting`.
- **DECOMPOSITION:** this IS the GraphQL variant.

## Goal
Prove GraphQL flaws (introspection/field-authz/node-IDOR/arg-injection). Emit `findings.json`
(`_contract/finding.schema.json`). DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## Steps  (action · tool · output)
1. Ingest schema; check introspection (`__schema`) · interceptor · `gql_tests.jsonl`
2. Field-level authz: as low-priv, query a field a role shouldn't see · multi-session · `gql_tests.jsonl`
3. Node IDOR: `node(id:)` / global ids to reach another owner's object · interceptor · `gql_tests.jsonl`
4. Injection via resolver args (SQLi/NoSQLi markers — hand to injection agents) · refs · `gql_tests.jsonl`
5. DoS feasibility (deep nesting / aliases / batching) — **assess + REPORT, do NOT execute** · synth · (into findings)
6. Capture PoC · interceptor · `poc/<id>/`
7. Rate (CVSS) + write finding · synth · `findings.json`
8. Emit report + curl · synth · `report.md`, `curl_commands.sh`
9. /REVIEW · `review.md` · 10. /VERIFY · `verify.md`

## Tools
- interceptor, introspection query, `graphw00f`/`clairvoyance`, `api-context/refs/api_techniques.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `api_context.json` (graphql schema/ops), `auth.env` (≥2 identities), `scope.yaml`

## Outputs
`gql_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** introspection + schema mapping.
- **Phase 2 (target-specific):** field-authz + node-IDOR + arg-injection + DoS feasibility + rating.

## Safety
**Never run a DoS query** (deep nesting / alias / batching amplification) — assess and report the
possibility only. Node-IDOR uses TEST accounts. Arg-injection confirmation hands off to the injection
agents. Scope-gate; audit-log.
