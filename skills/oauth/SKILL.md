# OAuth / OIDC Agent

> Variant of the auth family (siblings: `auth-bypass`, `jwt`). Consumes `auth_context.json` `oauth`
> config / flows with `variant_hint: oauth`.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest OAuth config → test redirect_uri manipulation (code/token leak) → test state/CSRF, code reuse, PKCE downgrade, implicit-flow leak, id_token validation → confirm token/code leak or account takeover/linking → rate → emit → review → verify.
- **TOOLS:** interceptor, an attacker redirect host (OOB), `auth-context/refs/auth_techniques.md`.
- **GOAL:** Confirm an OAuth/OIDC flaw — a flow manipulation that leaks a `code`/token or enables account takeover/linking. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `oauth_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `auth_context.json` (oauth: provider/flow/redirect_uri/state) + `auth.env` (test accounts) + `scope.yaml` (`oob.collaborator`). `refs/` = `auth-context/refs/`. Chains FROM `auth-context`; chains TO `reporting` (redirect_uri bypass ↔ `open-redirect`).
- **DECOMPOSITION:** this IS the OAuth variant.

## Goal
Prove an OAuth/OIDC flaw (code/token leak or takeover/linking). Emit `findings.json`
(`_contract/finding.schema.json`). DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## Steps  (action · tool · output)
1. Ingest OAuth config · `jq auth_context.json` · (into tests)
2. redirect_uri manipulation (suffix/subdomain/path/open-redirect in allowlist → leak `code`/token to OOB) · interceptor + OOB · `oauth_tests.jsonl`
3. state/CSRF (missing/replayable → login CSRF / account linking) · interceptor · `oauth_tests.jsonl`
4. code reuse · PKCE downgrade · implicit token-in-fragment leak · `id_token` aud/iss/sig validation · refs · `oauth_tests.jsonl`
5. Confirm leak/takeover (code/token received at OOB / account linked) on TEST accounts · OOB + interceptor · `poc/<id>/`
6. Rate (CVSS) + write finding · synth · `findings.json`
7. Emit report + curl · synth · `report.md`, `curl_commands.sh`
8. /REVIEW · `review.md` · 9. /VERIFY · `verify.md`

## Tools
- interceptor, an attacker redirect/OOB host, `auth-context/refs/auth_techniques.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `auth_context.json` (oauth config), `auth.env` (test accounts), `scope.yaml` (`oob.collaborator`)

## Outputs
`oauth_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** redirect_uri + state tests.
- **Phase 2 (target-specific):** code reuse / PKCE / implicit / id_token validation + leak/takeover confirmation + rating (approval-gated).

## Safety
TEST accounts for both attacker and victim; code/token leak goes to YOUR OOB host only; never capture a
real user's token; approval-gated; scope-gate; audit-log.
