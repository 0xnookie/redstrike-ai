# AD ADCS Agent

> Variant of the AD family (siblings: `ad-kerberos`, `ad-acl-abuse`, `ad-lateral-movement`). Consumes
> `ad_context.json` `adcs`. AD Certificate Services abuse (ESC1-ESC8).
> ACTIVE, HIGH-IMPACT, findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest ADCS templates + ESC flags → confirm the misconfig → abuse the lowest-risk ESC to obtain a cert as a TEST privileged principal → authenticate with it (PKINIT) → confirm → cleanup (revoke) → rate → emit → review → verify.
- **TOOLS:** `certipy` (`find`/`req`/`auth`/`relay`), `ntlmrelayx` (ESC8).
- **GOAL:** Confirm an abusable ADCS template/CA (ESC1-8) — demonstrated by issuing a cert that authenticates as a TEST privileged principal — then revoke it. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `adcs_tests.jsonl`, `findings.json`, `poc/`, `cleanup.md`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = `ad_context.json` (`adcs`, foothold) + `scope.yaml`. `refs/` = `ad-context/refs/`. Chains FROM `ad-context`; chains TO `ad-lateral-movement` + `reporting`.
- **DECOMPOSITION:** this IS the ADCS variant.

## Goal
Prove an ADCS misconfig (ESC) by issuing + using a cert for a TEST principal. Emit `findings.json`
(`_contract/finding.schema.json`). DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## Steps  (action · tool · output)
1. Ingest templates + ESC flags · `jq ad_context.json` + `certipy find` · (into tests)
2. Confirm the misconfig (ESC1 SAN / ESC2 any-purpose / ESC3 agent / ESC4 template-ACL / ESC6 / ESC7 CA-ACL / ESC8 relay) · `certipy` · `adcs_tests.jsonl`
3. Abuse the lowest-risk ESC: request a cert specifying a TEST privileged SAN (or relay for ESC8) · `certipy req`/`relay` · `poc/<id>/`
4. Authenticate with the cert (PKINIT → TGT/NT hash) as the TEST principal · `certipy auth` · `poc/<id>/`
5. Confirm access; record + **revoke** the issued cert · synth · `cleanup.md`
6. Rate (CVSS) + write finding · synth · `findings.json`
7. Emit report · synth · `report.md` · 8. /REVIEW · `review.md` · 9. /VERIFY · `verify.md`

## Tools
- `certipy` (`find`/`req`/`auth`/`relay`/`shadow`), `ntlmrelayx` (ESC8 + coercion)
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `ad_context.json` (`adcs`, foothold), `scope.yaml`

## Outputs
`adcs_tests.jsonl` · `findings.json` · `poc/` · `cleanup.md` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** confirm the ESC misconfig.
- **Phase 2 (target-specific):** issue + authenticate a cert for a test principal + revoke + rating (approval-gated).

## Safety
HIGH-IMPACT (ESC1/ESC8 → domain compromise) — **approval-gated**. Request a cert for a TEST privileged
principal to PROVE the ESC; authenticate to confirm; then **revoke** the issued certificate (recorded in
`cleanup.md`). Do NOT mint a DA cert and persist. ESC8 coercion needs approval (don't disrupt). Scope; audit-log; kill switch.
