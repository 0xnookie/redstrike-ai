# Privilege Escalation Agent

> Variant of the access-control family (sibling: `idor`). Consumes `authz_context.json` `endpoints`
> (role matrix). Function-level authorization: a low-priv identity performs a higher-priv action.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval** (admin actions). Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest role matrix → as low-priv A, invoke endpoints the matrix marks higher-role → confirm the privileged action executed (vertical) / another peer scope reachable (horizontal function) → test forced-browsing + method/role tampering → rate → emit → review → verify.
- **TOOLS:** multi-session interceptor, `authz-context/refs/`, matrix-diff.
- **GOAL:** Confirm privilege escalation — a low-priv account performs a function reserved for a higher role (missing function-level authz) — proven against the role matrix. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `privesc_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `authz_context.json` (endpoints/role matrix) + `auth.env` (low-priv + admin) + `scope.yaml`. `refs/` = `authz-context/refs/`. Chains FROM `authz-context`; chains TO `reporting`.
- **DECOMPOSITION:** this IS the function-level variant. Object-level → `idor`.

## Goal
Prove function-level privilege escalation against the role matrix. Emit `findings.json`
(`_contract/finding.schema.json`). DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## Steps  (action · tool · output)
1. Ingest the role matrix + identities · `jq authz_context.json` · (into tests)
2. As low-priv A, invoke endpoints the matrix reserves for a higher role · multi-session interceptor · `privesc_tests.jsonl`
3. Confirm the privileged action executed (state changed / admin data returned) · matrix-diff · `privesc_tests.jsonl`
4. Test forced-browsing (hidden admin paths), method tampering, role-param tampering · refs · `privesc_tests.jsonl`
5. Capture PoC (A performs the admin-only action) · interceptor · `poc/<id>/`
6. Rate (CVSS) + write finding · synth · `findings.json`
7. Emit report + curl · synth · `report.md`, `curl_commands.sh`
8. /REVIEW · `review.md` · 9. /VERIFY · `verify.md`

## Tools
- multi-session interceptor, matrix-diff, `authz-context/refs/authz_methodology.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `authz_context.json` (endpoints/role matrix), `auth.env` (low-priv + admin), `scope.yaml`

## Outputs
`privesc_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** invoke higher-role endpoints as low-priv; record outcomes vs the matrix.
- **Phase 2 (target-specific):** forced-browsing + method/role tampering + impact + rating (approval-gated).

## Safety
Performing an admin action is high-impact — **approval-gated**; use a TEST low-priv account; pick a
benign/reversible admin action to demonstrate (don't delete real data or change real users); scope-gate;
audit-log.
