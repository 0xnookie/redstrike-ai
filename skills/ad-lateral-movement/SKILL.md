# AD Lateral Movement Agent

> Variant of the AD family (siblings: `ad-kerberos`, `ad-acl-abuse`, `ad-adcs`). Consumes `ad_context.json`
> + credentials/hashes/tickets recovered by the siblings. Pass-the-hash/ticket, NTLM relay, remote exec.
> ACTIVE, HIGH-IMPACT, findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest recovered creds/hashes/tickets + targets → pass-the-hash/ticket to an in-scope host → (approval) NTLM relay + coercion → remote exec a BENIGN command → confirm access → cleanup → rate → emit → review → verify.
- **TOOLS:** `netexec` (PtH), `impacket` (`psexec`/`wmiexec`/`secretsdump`/`ticketer`), `evil-winrm`, `ntlmrelayx` + `Coercer`/`PetitPotam`.
- **GOAL:** Confirm lateral movement — authenticate to another in-scope host with a recovered credential/hash/ticket and run a benign command — demonstrating the reach, not full domain takeover. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `lateral_tests.jsonl`, `findings.json`, `poc/`, `cleanup.md`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = `ad_context.json` + recovered creds (from `ad-kerberos`/`ad-acl-abuse`/`ad-adcs`) + `scope.yaml`. `refs/` = `ad-context/refs/`. Chains FROM the AD siblings; chains TO `reporting` + `windows-privesc` (on a landed host).
- **DECOMPOSITION:** this IS the lateral-movement variant.

## Goal
Prove lateral reach with a recovered credential, benignly. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## Steps  (action · tool · output)
1. Ingest recovered creds/hashes/tickets + in-scope targets · `jq` · (into tests)
2. Pass-the-hash / pass-the-ticket / overpass-the-hash to an in-scope host · `netexec`/`impacket` · `lateral_tests.jsonl`
3. (Approval) NTLM relay + coercion (`ntlmrelayx` + `Coercer`) · relay · `lateral_tests.jsonl`
4. Remote exec a BENIGN command (`whoami`/`hostname`) to confirm access · `wmiexec`/`evil-winrm` · `poc/<id>/`
5. Confirm reach (which hosts, what privilege); record + remove any artifacts · synth · `cleanup.md`
6. Rate (CVSS) + write finding · synth · `findings.json`
7. Emit report · synth · `report.md` · 8. /REVIEW · `review.md` · 9. /VERIFY · `verify.md`

## Tools
- `netexec`, `impacket` (`psexec`/`wmiexec`/`smbexec`/`secretsdump`/`ticketer`), `evil-winrm`, `ntlmrelayx` + `Coercer`/`PetitPotam`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `ad_context.json` + recovered creds (AD siblings), `scope.yaml`

## Outputs
`lateral_tests.jsonl` · `findings.json` · `poc/` · `cleanup.md` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** PtH/PtT to an in-scope host + benign exec.
- **Phase 2 (target-specific):** relay/coercion + reach mapping + cleanup + rating (approval-gated).

## Safety
HIGH-IMPACT — **approval-gated** + kill switch. Authenticate + run a BENIGN command (`whoami`) to prove
reach — **no** destructive actions, no real data theft, no persistence/backdoors, no disruptive coercion on
prod. In-scope hosts only. Remove any exec artifacts (services, files) — `cleanup.md`. Scope; audit-log.
