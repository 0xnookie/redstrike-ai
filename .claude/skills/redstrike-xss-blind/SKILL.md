---
name: redstrike-xss-blind
description: Run the Redstrike blind-XSS hunt (executor) — token-tagged OOB beacons across unseen surfaces, async callbacks — then gate and hand off to the xss-blind-verify reviewer agent.
---

Run the Redstrike **xss-blind** methodology (canonical spec: `skills/xss-blind/`).

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`; `oob.collaborator` is required; staff-facing injection leans on approval; benign beacons only.
2. **Execute:** follow `skills/xss-blind/SKILL.md`; consume `<engagement>/xss-context/xss_context.json` (`variant_hint:blind`) + `xss-stored` handoffs; work `skills/xss-blind/checklist.md`; use `skills/xss-blind/refs/`. Write outputs to `<engagement>/xss-blind/` (incl. `cleanup.md`). Keep the OOB listener up for the window — callbacks are async.
3. **Coverage:** copy your filled checklist into `<engagement>/xss-blind/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/xss-blind --out <engagement>/xss-blind` → fix + re-run until exit 0. (Empty `callbacks.jsonl` is a valid pass.)
5. **Reviewer:** launch the `xss-blind-verify` subagent on `<engagement>/xss-blind`. A finding requires an attributable callback; only `accepted` findings go to reporting.
