# BOLA / BFLA Agent

> Variant of the API family (sibling: `graphql`). Consumes `api_context.json` endpoints with
> `variant_hint: bola-bfla`. API object/function-level authz + excessive data + mass assignment.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval** (BFLA). Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest endpoints + identities → BOLA (swap object id across identities) → BFLA (low-priv calls privileged op) → excessive-data (compare returned vs needed fields) → mass-assignment (extra privileged fields) → rate → emit → review → verify.
- **TOOLS:** multi-session interceptor, `api-context/refs/api_techniques.md`, request-diff.
- **GOAL:** Confirm API authorization/exposure flaws (BOLA/BFLA/excessive data/mass assignment) with two test identities. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `api_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `api_context.json` (endpoints, object params, roles, fields) + `auth.env` (≥2 identities) + `scope.yaml`. `refs/` = `api-context/refs/`. Chains FROM `api-context`; cross-refs `idor`/`privesc`. Chains TO `reporting`.
- **DECOMPOSITION:** this IS the REST object/function-authz variant (GraphQL → `graphql`).

## Goal
Prove API authz/exposure flaws. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## Steps  (action · tool · output)
1. Ingest endpoints + identities · `jq api_context.json` · (into tests)
2. BOLA: as identity A, access B's object id (path/body) · multi-session interceptor · `api_tests.jsonl`
3. BFLA: as low-priv A, call a privileged operation (method+path/override) · interceptor · `api_tests.jsonl`
4. Excessive data: compare returned fields vs what's needed (PII/internal flags) · request-diff · `api_tests.jsonl`
5. Mass assignment: send `role`/`isAdmin`/`verified` to create/update · refs · `api_tests.jsonl`
6. Capture PoC · interceptor · `poc/<id>/`
7. Rate (CVSS) + write finding · synth · `findings.json`
8. Emit report + curl · synth · `report.md`, `curl_commands.sh`
9. /REVIEW · `review.md` · 10. /VERIFY · `verify.md`

## Tools
- multi-session interceptor, request-diff, `api-context/refs/api_techniques.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `api_context.json` (endpoints, object params, roles, fields), `auth.env` (≥2 identities), `scope.yaml`

## Outputs
`api_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** BOLA + excessive-data across identities.
- **Phase 2 (target-specific):** BFLA + mass-assignment + rating (approval-gated).

## Safety
TWO TEST accounts (never real-user data); BFLA privileged actions **approval-gated** + benign/reversible;
scope-gate; audit-log. Overlaps `idor`/`privesc` — de-dupe at reporting.
