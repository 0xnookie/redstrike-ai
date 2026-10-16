# IDOR Agent

> Variant of the access-control family (sibling: `privesc`). Consumes `authz_context.json` `objects`
> + `mass_assign_candidates`. Object-level authorization: access/modify ANOTHER owner's resource.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md`. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest object refs + identities → as identity A, request B's object id → confirm cross-owner access (data returned / action performed) → test id enumeration + mass-assignment → rate → emit → review → verify.
- **TOOLS:** multi-session interceptor, `authz-context/refs/`, request-diff (A vs B vs unauth).
- **GOAL:** Confirm IDOR — a low-priv account accesses/modifies a resource owned by another account because the server omits the ownership check — proven with two test accounts. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `access_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `authz_context.json` (objects, mass-assign) + `auth.env` (≥2 identities) + `scope.yaml`. `refs/` = `authz-context/refs/`. Chains FROM `authz-context`; chains TO `reporting`.
- **DECOMPOSITION:** this IS the object-level variant (incl. mass-assignment). Function-level → `privesc`.

## Goal
Prove cross-owner object access/modification (or mass-assignment of a privileged field). Emit
`findings.json` (`_contract/finding.schema.json`). DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## Steps  (action · tool · output)
1. Ingest object refs + identities from `authz_context.json` · `jq` · (into tests)
2. As identity A, request identity B's object id (GET/PUT/DELETE) · multi-session interceptor · `access_tests.jsonl`
3. Confirm cross-owner access (B's data returned / B's resource modified) · request-diff (A vs B) · `access_tests.jsonl`
4. Test id enumeration (sequential) + mass-assignment (set `owner_id`/`role`/`is_admin`) · refs · `access_tests.jsonl`
5. Capture PoC (A's session + B's id → B's data) · interceptor · `poc/<id>/`
6. Rate (CVSS) + write finding · synth · `findings.json`
7. Emit report + curl · synth · `report.md`, `curl_commands.sh`
8. /REVIEW · `review.md` · 9. /VERIFY · `verify.md`

## Tools
- multi-session interceptor (2+ profiles), request-diff, `authz-context/refs/authz_methodology.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `authz_context.json` (objects, mass_assign), `auth.env` (≥2 identities), `scope.yaml`

## Outputs
`access_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** cross-owner access tests on mapped objects.
- **Phase 2 (target-specific):** id enumeration + mass-assignment + impact + rating.

## Safety
Use TEST accounts you control for BOTH A and B — never access a real user's data to prove IDOR.
Create two of your own accounts/resources; demonstrate A→B on those. Modifications on a test resource
only, reversible; scope-gate; audit-log.
