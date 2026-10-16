---
name: redstrike-xss-reflected
description: Run the Redstrike reflected-XSS hunt (executor) — confirm reflected XSS that executes in a real browser — then gate and hand off to the xss-reflected-verify reviewer agent.
---

Run the Redstrike **xss-reflected** methodology (canonical spec: `skills/xss-reflected/`).

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`; stop on out-of-scope / closed-window targets.
2. **Execute:** follow `skills/xss-reflected/SKILL.md`; consume `<engagement>/xss-context/xss_context.json`; work `skills/xss-reflected/checklist.md` (mark `- [x]` only when a step's artifact exists); use `skills/xss-reflected/refs/` + the anti-automation ladder. Write outputs to `<engagement>/xss-reflected/`.
3. **Coverage:** copy your filled checklist into `<engagement>/xss-reflected/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/xss-reflected --out <engagement>/xss-reflected` → fix + re-run until exit 0.
5. **Reviewer:** launch the `xss-reflected-verify` subagent on `<engagement>/xss-reflected`. Only `accepted` findings go to reporting.
