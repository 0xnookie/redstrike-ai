# Authentication Bypass Agent

> Variant of the auth family (siblings: `jwt`, `oauth`). Consumes `auth_context.json` flows with
> `variant_hint: auth-bypass` (login, MFA, reset, session).
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest auth flows → test logic bypass (forced browsing, response tampering, 2FA skip, session fixation, reset weaknesses) → confirm authenticated/privileged state reached without valid auth → rate → emit → review → verify.
- **TOOLS:** interceptor, `auth-context/refs/auth_techniques.md`.
- **GOAL:** Confirm an authentication/step bypass — reaching an authenticated or post-2FA state without completing the intended auth — on a TEST account. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `bypass_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `auth_context.json` (flows, session) + `auth.env` (test account) + `scope.yaml`. `refs/` = `auth-context/refs/`. Chains FROM `auth-context`; chains TO `reporting` (reset host-poison → `host-header`).
- **DECOMPOSITION:** this IS the auth-bypass variant (JWT → `jwt`, OAuth → `oauth`).

## Goal
Prove an authentication or required-step bypass. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## Steps  (action · tool · output)
1. Ingest auth flows + session mechanism · `jq auth_context.json` · (into tests)
2. Test logic bypass: forced browsing past login; response tampering; 2FA-step skip; session fixation; reset weaknesses · interceptor + refs · `bypass_tests.jsonl`
3. Confirm authed/privileged state reached without valid auth (benign) · interceptor · `bypass_tests.jsonl`
4. Capture PoC (the bypass → authed access) · interceptor · `poc/<id>/`
5. Rate (CVSS) + write finding · synth · `findings.json`
6. Emit report + curl · synth · `report.md`, `curl_commands.sh`
7. /REVIEW · `review.md` · 8. /VERIFY · `verify.md`

## Tools
- interceptor, `auth-context/refs/auth_techniques.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `auth_context.json` (flows, session), `auth.env` (test account), `scope.yaml`

## Outputs
`bypass_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** session + forced-browsing + response-tampering tests.
- **Phase 2 (target-specific):** 2FA/reset/fixation bypass + rating (approval-gated).

## Safety
TEST accounts only; **no real brute-force** (few OTP/password attempts, rate-limited — never lock out
real users); reset/MFA flows **approval-gated**; benign proof; scope-gate; audit-log.
