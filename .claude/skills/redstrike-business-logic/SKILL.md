---
name: redstrike-business-logic
description: Run the Redstrike business-logic hunt (executor) — bespoke: model workflows + invariants, break them for impact — then gate and hand off to the business-logic-verify reviewer agent.
---

Run the Redstrike **business-logic** methodology (canonical spec: `skills/business-logic/`). This is BESPOKE — tests are derived from THIS app's workflows, not a payload list.

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. Use **test accounts**; keep changes reversible; never complete real purchases / move real funds; approval for payment/production state; clean up race-created duplicate state.
2. **Execute:** follow `skills/business-logic/SKILL.md`; consume `skills/js-analysis/feature_map.md` + `apis.json` + multi-role `auth.env`; work `skills/business-logic/checklist.md`; use `skills/business-logic/refs/`. Write outputs to `<engagement>/business-logic/` (incl. `workflow_model.md`, `invariants.json`).
3. **Coverage:** copy your filled checklist into `<engagement>/business-logic/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/business-logic --out <engagement>/business-logic` → fix + re-run until exit 0.
5. **Reviewer:** launch the `business-logic-verify` subagent on `<engagement>/business-logic`. Only `accepted` findings go to reporting.
