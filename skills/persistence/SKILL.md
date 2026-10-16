# Persistence Agent

> ATOMIC agent (post-ex / MITRE TA0003) — demonstrate, BENIGNLY and reversibly, that the environment allows
> undetected persistence, then remove it. The finding is the missing control, not a planted backdoor.
> ACTIVE, HIGH-RISK, findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** enumerate persistence opportunities on the landed host → install ONE BENIGN MARKER persistence (writes a harmless marker when it fires) → prove it re-triggers (survives logoff/reboot where applicable) → REMOVE it completely → rate (detectability + control gap) → emit → review → verify.
- **TOOLS:** native OS mechanisms, `refs/persistence.md`.
- **GOAL:** Confirm a persistence exposure — a mechanism that would let an attacker survive reboot/credential-change undetected — by installing and then fully REMOVING a benign marker, proving the gap in monitoring/controls. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `persist_enum.json`, `persist_tests.jsonl`, `findings.json`, `poc/`, `cleanup.md`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = a landed host (from privesc / lateral movement) + `scope.yaml`. `refs/` = `persistence.md`. Chains FROM `linux-privesc`/`windows-privesc`/`ad-*`; chains TO `reporting`.
- **DECOMPOSITION:** n/a (atomic).

## Goal
Prove a benign, reversible persistence exposure + whether it was detected. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## What do we want
- A persistence opportunity the current access allows (user/host autoruns, scheduled jobs, service/unit, startup, key-based)
- A BENIGN MARKER that fires via that mechanism (writes a timestamped marker file, nothing else)
- Proof it re-triggered + whether defenses alerted — then COMPLETE removal

## Steps  (action · tool · output)
1. Enumerate persistence opportunities for the current privilege · native enum + refs · `persist_enum.json`
2. Install ONE benign marker persistence (writes a harmless marker on trigger) · native · `persist_tests.jsonl`
3. Trigger it (logoff/reboot/schedule) + confirm the marker appeared · native · `poc/<id>/`
4. Note detectability (did logging/EDR flag it?) · synth · `persist_tests.jsonl`
5. REMOVE the mechanism completely + confirm it's gone · native · `cleanup.md`
6. Rate (CVSS — control/monitoring gap) + write finding · synth · `findings.json`
7. Emit report · synth · `report.md` · 8. /REVIEW · `review.md` · 9. /VERIFY · `verify.md`

## Tools
- native OS mechanisms (scheduler, service/unit manager, autorun locations, key-based), `refs/persistence.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- a landed in-scope host, `scope.yaml`

## Outputs
`persist_enum.json` · `persist_tests.jsonl` · `findings.json` · `poc/` · `cleanup.md` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** enumerate opportunities.
- **Phase 2 (target-specific):** benign marker install → trigger proof → COMPLETE removal + rating (approval-gated).

## Safety
Post-ex, **approval-gated**. The payload is a BENIGN MARKER only (writes a harmless file) — **never** a real
backdoor, shell, C2, or anything that grants access. Install exactly ONE, prove it, then REMOVE it completely
and verify removal (`cleanup.md`); nothing persistent is left behind. No credential changes, no disabling
defenses. In-scope host only; audit-log. If removal can't be fully verified, escalate immediately.
