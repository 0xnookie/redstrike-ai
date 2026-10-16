# AD ACL Abuse Agent

> Variant of the AD family (siblings: `ad-kerberos`, `ad-adcs`, `ad-lateral-movement`). Consumes
> `ad_context.json` `acl_edges`. ACL/DACL abuse, shadow credentials, DCSync.
> ACTIVE, HIGH-IMPACT, findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest ACL edges → abuse the edge on a TEST target (ForceChangePassword / AddMember / AddKeyCredentialLink=shadow-creds / WriteDacl→grant) → DCSync (approval, one test account) → confirm → cleanup → rate → emit → review → verify.
- **TOOLS:** `bloodyAD`/`dacledit`/`net rpc`, `pywhisker`/`certipy shadow`, `impacket secretsdump` (DCSync).
- **GOAL:** Confirm an abusable ACL edge — demonstrated by exercising it on a TEST principal (reset a test user, add a shadow credential + authenticate, grant then DCSync one test account) — then revert. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `acl_tests.jsonl`, `findings.json`, `poc/`, `cleanup.md`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = `ad_context.json` (`acl_edges`, foothold) + `scope.yaml`. `refs/` = `ad-context/refs/`. Chains FROM `ad-context`; chains TO `ad-lateral-movement` + `reporting`.
- **DECOMPOSITION:** this IS the ACL-abuse variant.

## Goal
Prove an abusable ACL edge, demonstrated + reverted. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## Steps  (action · tool · output)
1. Ingest ACL edges + foothold · `jq ad_context.json` · (into tests)
2. Abuse the edge on a TEST target:
   - `ForceChangePassword` → reset a TEST user's password · `bloodyAD`/`net rpc` · `acl_tests.jsonl`
   - `AddKeyCredentialLink` → shadow credential → PKINIT → NT hash · `pywhisker`/`certipy shadow` · `acl_tests.jsonl`
   - `WriteDacl`/`GenericAll` → grant a right then revert · `dacledit` · `acl_tests.jsonl`
   - `AddMember` → add a TEST account to a group then remove · `bloodyAD` · `acl_tests.jsonl`
3. (Approval) DCSync a SINGLE test account (not the whole domain) · `secretsdump -just-dc-user <test>` · `poc/<id>/`
4. Confirm the abuse worked; revert every change · synth · `poc/<id>/`, `cleanup.md`
5. Rate (CVSS) + write finding · synth · `findings.json`
6. Emit report · synth · `report.md` · 7. /REVIEW · `review.md` · 8. /VERIFY · `verify.md`

## Tools
- `bloodyAD`, `dacledit.py`, `net rpc`, `pywhisker`/`certipy shadow`, `impacket secretsdump` (DCSync)
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `ad_context.json` (`acl_edges`, foothold), `scope.yaml`

## Outputs
`acl_tests.jsonl` · `findings.json` · `poc/` · `cleanup.md` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** abuse the edge on a test target (reset/shadow-cred/add-member).
- **Phase 2 (target-specific):** WriteDacl-grant / single-account DCSync + revert + rating (approval-gated).

## Safety
HIGH-IMPACT — **approval-gated**. Exercise edges against TEST principals you can revert; **always revert**
(passwords, DACLs, group memberships, shadow creds) — tracked in `cleanup.md`. DCSync a SINGLE test account
to prove the right, **never** the whole domain / krbtgt. Scope; audit-log; kill switch.
