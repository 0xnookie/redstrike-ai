---
name: redstrike-race-condition
description: Run the Redstrike race-condition hunt (executor) — TOCTOU + limit-overrun races on single-use/limited state-changing actions, collapsed with the single-packet attack and confirmed by a before/after state break on a test account — then gate and hand off to the race-condition-verify reviewer agent.
---

Run the Redstrike **race-condition** methodology (canonical spec: `skills/race-condition/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`; approval required (state-changing); use a TEST account; bounded concurrency (tens, not thousands — a correctness proof, not a DoS); revert any state.
2. **Execute:** follow `skills/race-condition/SKILL.md`; consume `skills/js-analysis/` endpoints+forms + `business-logic` single-use/limited actions; work `skills/race-condition/checklist.md`; use `skills/race-condition/refs/`. Write outputs to `<engagement>/race-condition/`.
3. **Coverage:** copy your filled checklist into `<engagement>/race-condition/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/race-condition --out <engagement>/race-condition` → fix + re-run until exit 0.
5. **Reviewer:** launch the `race-condition-verify` subagent on `<engagement>/race-condition`. Only `accepted` findings go to reporting.
