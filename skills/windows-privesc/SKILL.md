# Windows Privilege Escalation Agent

> POST-EXPLOITATION skill. Runs on an in-scope Windows host where we have a foothold (from web RCE,
> AD lateral movement, …). Enumerates + confirms a privesc vector to SYSTEM/admin.
> ACTIVE, HIGH-RISK, findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** confirm foothold → **`whoami /all`** (token privileges first) → **enumerate with winPEAS** (`log=enum.txt`, triage RED hits) + PowerUp/Seatbelt + WES-NG + manual → identify vectors (token Se*→potato/SAM/utilman, weak service perms/DACL, unquoted path, AlwaysInstallElevated, scheduled-task/autorun, DLL hijack, saved creds) → exploit the lowest-risk vector to SYSTEM/admin BENIGNLY → confirm (`whoami`=system) → cleanup → rate → emit → review → verify.
- **TOOLS:** **`winPEAS`** (spine) + `whoami /all`, `PowerUp`/`SharpUp`, `Seatbelt`, `PrivescCheck`, `accesschk`, `WES-NG` (offline), potato tools (`PrintSpoofer`/`GodPotato`); `refs/enumeration.md` (winPEAS-first recon) + `refs/windows_privesc_playbook.md` (vectors).
- **GOAL:** Confirm a Windows local privesc vector by escalating to SYSTEM/admin BENIGNLY (prove `whoami`, no persistence/damage), on an in-scope host. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `enum.txt` (raw winPEAS/whoami/manual), `enum.json` (distilled vectors), `privesc_tests.jsonl`, `findings.json`, `poc/`, `cleanup.md`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = the foothold (host + user) from the engagement + `scope.yaml`. `refs/` = `enumeration.md` (winPEAS-first recon playbook) + `windows_privesc_playbook.md` (vector → benign SYSTEM). Chains FROM web RCE / `ad-lateral-movement`; chains TO `reporting` + `ad-*` (if domain-joined).
- **DECOMPOSITION:** n/a (post-ex skill).

## Goal
Prove a Windows privesc vector (benign SYSTEM/admin). Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## What do we want
- A full enumeration (services, token privileges, AlwaysInstallElevated, autoruns, DLL paths, saved creds, patch level)
- The vector(s) that escalate to SYSTEM/admin + the exploitation path
- A BENIGN SYSTEM proof (`whoami` = nt authority\system), cleaned up

## Steps  (action · tool · output)
1. Confirm the foothold + run **`whoami /all`** (token privileges decide everything) · `whoami /all` · (into context)
2. Enumerate: run **winPEAS** (`log=enum.txt`, triage RED hits), PowerUp `Invoke-AllChecks` / Seatbelt / PrivescCheck, WES-NG offline vs `systeminfo`, `accesschk` services, then a manual pass to confirm · `refs/enumeration.md` · `enum.txt` + `enum.json`
3. Identify vectors (token Se* → potato/SAM-read/utilman-swap, weak service perms/DACL via accesschk, unquoted service path, AlwaysInstallElevated, scheduled-task/autorun hijack, DLL hijack, saved creds via cmdkey/unattend/web.config) · `refs/windows_privesc_playbook.md` · `privesc_tests.jsonl`
4. Exploit the lowest-risk vector to SYSTEM/admin BENIGNLY · `refs/windows_privesc_playbook.md` · `poc/<id>/`
5. Confirm SYSTEM (`whoami` = nt authority\system) with a benign command; record + revert anything created · synth · `cleanup.md`
6. Rate (CVSS) + write finding · synth · `findings.json`
7. Emit report · synth · `report.md` · 8. /REVIEW · `review.md` · 9. /VERIFY · `verify.md`

## Tools
- **`winPEAS`** (enumeration spine) + `whoami /all`, `PowerUp`/`SharpUp`, `Seatbelt`, `PrivescCheck`,
  `accesschk`, `WES-NG` (offline), `PrintSpoofer`/`GodPotato` (SeImpersonate); `refs/enumeration.md` + `refs/windows_privesc_playbook.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- the foothold (in-scope host + user), `scope.yaml`, `refs/enumeration.md`, `refs/windows_privesc_playbook.md`

## Outputs
`enum.txt` · `enum.json` · `privesc_tests.jsonl` · `findings.json` · `poc/` · `cleanup.md` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** enumeration + vector identification.
- **Phase 2 (target-specific):** benign exploitation to SYSTEM + confirmation + cleanup + rating (approval-gated).

## Safety
Post-ex on a real host — **approval-gated** + kill switch. Escalate BENIGNLY (prove `whoami`=SYSTEM, run a
benign command) — **no** persistence/backdoors, no destruction, no credential dumping beyond what proves
the vector. Prefer the lowest-risk vector; avoid anything that could crash prod (report feasibility instead).
Revert anything created (services, files, registry) — `cleanup.md`. In-scope host only; audit-log.
