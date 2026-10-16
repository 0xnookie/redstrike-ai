---
name: redstrike-csrf
description: Run the Redstrike CSRF hunt (executor) — state-changing requests lacking effective anti-CSRF, confirmed cross-origin — then gate and hand off to the csrf-verify reviewer agent.
---

Run the Redstrike **csrf** methodology (canonical spec: `skills/csrf/`).

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`; use a test account; no destructive change on a real account without approval.
2. **Execute:** follow `skills/csrf/SKILL.md`; consume `skills/js-analysis/` endpoints/forms; work `skills/csrf/checklist.md`; use `skills/csrf/refs/`. Write outputs to `<engagement>/csrf/`.
3. **Coverage:** copy your filled checklist into `<engagement>/csrf/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/csrf --out <engagement>/csrf` → fix + re-run until exit 0.
5. **Reviewer:** launch the `csrf-verify` subagent on `<engagement>/csrf`. Only `accepted` findings go to reporting.
