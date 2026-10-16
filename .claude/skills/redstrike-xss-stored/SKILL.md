---
name: redstrike-xss-stored
description: Run the Redstrike stored-XSS hunt (executor) — persist->render with cross-user execution — then gate and hand off to the xss-stored-verify reviewer agent.
---

Run the Redstrike **xss-stored** methodology (canonical spec: `skills/xss-stored/`).

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`; stop on out-of-scope / closed-window targets. Stored payloads have blast radius — benign only; approval for real-user surfaces.
2. **Execute:** follow `skills/xss-stored/SKILL.md`; consume `<engagement>/xss-context/xss_context.json` (points with `persists:true`); work `skills/xss-stored/checklist.md`; use `skills/xss-stored/refs/`. Write outputs to `<engagement>/xss-stored/` (incl. `cleanup.md`).
3. **Coverage:** copy your filled checklist into `<engagement>/xss-stored/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/xss-stored --out <engagement>/xss-stored` → fix + re-run until exit 0.
5. **Reviewer:** launch the `xss-stored-verify` subagent on `<engagement>/xss-stored`. Only `accepted` findings go to reporting.
