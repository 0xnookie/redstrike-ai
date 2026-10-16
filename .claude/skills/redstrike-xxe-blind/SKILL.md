---
name: redstrike-xxe-blind
description: Run the Redstrike blind XXE hunt (executor) — external-DTD / parameter-entity resolution confirmed by an attributable OOB callback (+ optional benign file exfil) — then gate and hand off to the xxe-blind-verify reviewer agent.
---

Run the Redstrike **xxe-blind** methodology (canonical spec: `skills/xxe-blind/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. `oob.collaborator` required; benign OOB; exfil only a non-sensitive file (`/etc/hostname`); **no DoS**; **get approval** for file exfil.
2. **Execute:** follow `skills/xxe-blind/SKILL.md`; consume `<engagement>/xxe-context/xxe_context.json` (blind sinks); work `skills/xxe-blind/checklist.md`; use `skills/xxe-context/refs/`. Write outputs to `<engagement>/xxe-blind/`. Keep the OOB listener up — callbacks are async.
3. **Coverage:** copy your filled checklist into `<engagement>/xxe-blind/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/xxe-blind --out <engagement>/xxe-blind` → fix + re-run until exit 0. (Empty `callbacks.jsonl` is a valid pass.)
5. **Reviewer:** launch the `xxe-blind-verify` subagent on `<engagement>/xxe-blind`. A finding requires an attributable callback; only `accepted` findings go to reporting.
