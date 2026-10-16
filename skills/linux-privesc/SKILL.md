# Linux Privilege Escalation Agent

> POST-EXPLOITATION skill. Runs on an in-scope Linux host where we have a foothold (from web RCE, SSH,
> AD lateral movement, …). Enumerates + confirms a privesc vector to root.
> ACTIVE, HIGH-RISK, findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** confirm foothold → enumerate (automated + manual) → identify vectors (SUID/sudo/cron/caps/kernel/PATH/writable/group) → exploit the lowest-risk vector to root BENIGNLY → confirm (`id`=root) → cleanup → rate → emit → review → verify.
- **TOOLS:** `linpeas`/`linenum`, `pspy`, `GTFOBins`, manual enum; `refs/linux_privesc_playbook.md`.
- **GOAL:** Confirm a Linux local privilege-escalation vector by escalating to root BENIGNLY (prove `id`, no persistence/damage), on an in-scope host. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `enum.json`, `privesc_tests.jsonl`, `findings.json`, `poc/`, `cleanup.md`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = the foothold (host + user) from the engagement + `scope.yaml`. `refs/` = `linux_privesc_playbook.md`. Chains FROM web RCE / `ad-lateral-movement` / SSH; chains TO `reporting`.
- **DECOMPOSITION:** n/a (post-ex skill).

## Goal
Prove a Linux privesc vector (benign root). Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## What do we want
- A full enumeration (SUID/SGID, sudo, cron, capabilities, kernel, PATH, writable files/services, group memberships, creds)
- The vector(s) that escalate to root + the exploitation path
- A BENIGN root proof (`id`), cleaned up

## Steps  (action · tool · output)
1. Confirm the foothold (host + current user) · read · (into context)
2. Enumerate (automated + manual) · `linpeas` + `pspy` + manual · `enum.json`
3. Identify vectors (SUID→GTFOBins, sudo→GTFOBins, writable cron, caps, kernel, PATH hijack, writable service, docker/lxd/disk group) · `refs` · `privesc_tests.jsonl`
4. Exploit the lowest-risk vector to root BENIGNLY · `refs/linux_privesc_playbook.md` · `poc/<id>/`
5. Confirm root (`id` = uid=0) with a benign command; record + revert anything created · synth · `cleanup.md`
6. Rate (CVSS) + write finding · synth · `findings.json`
7. Emit report · synth · `report.md` · 8. /REVIEW · `review.md` · 9. /VERIFY · `verify.md`

## Tools
- `linpeas`/`linenum`, `pspy`, `GTFOBins`, manual enum; `refs/linux_privesc_playbook.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- the foothold (in-scope host + user), `scope.yaml`, `refs/linux_privesc_playbook.md`

## Outputs
`enum.json` · `privesc_tests.jsonl` · `findings.json` · `poc/` · `cleanup.md` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** enumeration + vector identification.
- **Phase 2 (target-specific):** benign exploitation to root + confirmation + cleanup + rating (approval-gated).

## Safety
Post-ex on a real host — **approval-gated** + kill switch. Escalate BENIGNLY (prove `id=root`, run a benign
command) — **no** persistence/backdoors, no destruction, no data theft. Prefer the lowest-risk vector; avoid
kernel exploits that could crash prod (note feasibility instead if risky). Revert anything created
(`cleanup.md`). In-scope host only; audit-log.
