# AD Kerberos Agent

> Variant of the AD family (siblings: `ad-acl-abuse`, `ad-adcs`, `ad-lateral-movement`). Consumes
> `ad_context.json` principal flags. Kerberoasting, AS-REP roasting, delegation abuse, golden/silver tickets.
> ACTIVE, HIGH-IMPACT, findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest flagged principals → Kerberoast (TGS → crack offline) → AS-REP roast → delegation abuse (unconstrained/constrained/RBCD) → (approval) golden/silver ticket capability → confirm → cleanup → rate → emit → review → verify.
- **TOOLS:** `impacket` (`GetUserSPNs`/`GetNPUsers`/`getST`/`ticketer`), `netexec`, `hashcat` (offline), `rubeus` (Windows).
- **GOAL:** Confirm a Kerberos attack vector — a crackable roastable hash, an abusable delegation path, or ticket-forging capability — demonstrated, not a full domain takeover. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `kerberos_tests.jsonl`, `findings.json`, `poc/`, `cleanup.md`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = `ad_context.json` (principals/flags + foothold) + `scope.yaml`. `refs/` = `ad-context/refs/`. Chains FROM `ad-context`; chains TO `ad-lateral-movement` + `reporting`.
- **DECOMPOSITION:** this IS the Kerberos variant.

## Goal
Prove a Kerberos vector (roast/delegation/ticket), demonstrated. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## Steps  (action · tool · output)
1. Ingest flagged principals + foothold · `jq ad_context.json` · (into tests)
2. Kerberoast (request TGS for SPN accounts) → crack OFFLINE · `GetUserSPNs` + `hashcat -m 13100` · `kerberos_tests.jsonl`
3. AS-REP roast (no-preauth accounts) → crack OFFLINE · `GetNPUsers` + `hashcat -m 18200` · `kerberos_tests.jsonl`
4. Delegation abuse (unconstrained TGT capture / constrained S4U / RBCD) — demonstrate on a test target · `impacket` · `kerberos_tests.jsonl`
5. (Approval) golden/silver ticket CAPABILITY (forge for a test principal, don't persist) · `ticketer` · `poc/<id>/`
6. Confirm the vector (cracked a weak test SPN / S4U'd to a test service) · synth · `poc/<id>/`
7. Record + remove any created objects (RBCD, tickets) · synth · `cleanup.md`
8. Rate (CVSS) + write finding · synth · `findings.json`
9. Emit report · synth · `report.md` · 10. /REVIEW · `review.md` · 11. /VERIFY · `verify.md`

## Tools
- `impacket` (`GetUserSPNs`/`GetNPUsers`/`getST`/`ticketer`), `netexec`, `hashcat` (OFFLINE), `rubeus`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `ad_context.json` (principals/flags, foothold), `scope.yaml`

## Outputs
`kerberos_tests.jsonl` · `findings.json` · `poc/` · `cleanup.md` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** Kerberoast + AS-REP (offline crack).
- **Phase 2 (target-specific):** delegation abuse + ticket capability + cleanup + rating (approval-gated).

## Safety
HIGH-IMPACT (domain) — **approval-gated**. Crack hashes **offline** only. **Demonstrate the vector** (crack a
weak test SPN, S4U to a test service, forge a ticket for a test principal) — do NOT golden-ticket + persist,
do NOT compromise real DA. Clean up RBCD/tickets/created objects (`cleanup.md`). Scope; audit-log; kill switch.
