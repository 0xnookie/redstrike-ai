---
name: redstrike-cors
description: Run the Redstrike CORS-misconfig hunt (executor) — credentialed cross-origin reads of sensitive data — then gate and hand off to the cors-verify reviewer agent.
---

Run the Redstrike **cors** methodology (canonical spec: `skills/cors/`).

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`; use a test account; don't retain real user data read during testing.
2. **Execute:** follow `skills/cors/SKILL.md`; consume `skills/js-analysis/` endpoints + `apis.json`; work `skills/cors/checklist.md`; use `skills/cors/refs/`. Write outputs to `<engagement>/cors/`.
3. **Coverage:** copy your filled checklist into `<engagement>/cors/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/cors --out <engagement>/cors` → fix + re-run until exit 0.
5. **Reviewer:** launch the `cors-verify` subagent on `<engagement>/cors`. Only `accepted` findings go to reporting.
