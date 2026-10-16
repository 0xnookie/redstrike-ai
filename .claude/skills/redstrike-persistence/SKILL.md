---
name: redstrike-persistence
description: Run the Redstrike persistence hunt (post-exploitation) — demonstrate BENIGNLY and reversibly that the environment allows undetected persistence via a named mechanism, then REMOVE it completely (the finding is the missing control, not a backdoor) — then gate and hand off to the persistence-verify reviewer agent. High-risk, approval-gated.
---

Run the Redstrike **persistence** methodology (canonical spec: `skills/persistence/`). Post-exploitation, HIGH-RISK.

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Get approval** + kill switch. The payload is a BENIGN MARKER only (writes a harmless timestamped file) — **never** a backdoor/shell/C2, no credential change, no disabling defenses. Install exactly ONE, prove it re-triggers, then REMOVE it completely and VERIFY removal (`cleanup.md`). In-scope host only.
2. **Execute:** follow `skills/persistence/SKILL.md` on the foothold host — enumerate opportunities → install one benign marker → prove re-trigger + note detectability → complete removal; work `skills/persistence/checklist.md`; use `skills/persistence/refs/`. Write outputs to `<engagement>/persistence/`.
3. **Coverage:** copy your filled checklist into `<engagement>/persistence/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/persistence --out <engagement>/persistence` → fix + re-run until exit 0.
5. **Reviewer:** launch the `persistence-verify` subagent on `<engagement>/persistence`. Only `accepted` findings go to reporting.
