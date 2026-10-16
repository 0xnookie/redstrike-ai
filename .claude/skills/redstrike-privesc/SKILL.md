---
name: redstrike-privesc
description: Run the Redstrike privilege-escalation hunt (executor) — function-level access control: a low-priv identity performs a higher-role action — then gate and hand off to the privesc-verify reviewer agent.
---

Run the Redstrike **privesc** methodology (canonical spec: `skills/privesc/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. Performing an admin action is high-impact — **get approval**; use a TEST low-priv account; pick a benign/reversible admin action to demonstrate (don't delete real data / change real users).
2. **Execute:** follow `skills/privesc/SKILL.md`; consume `<engagement>/authz-context/authz_context.json` (role matrix) + `auth.env` (low-priv + admin); work `skills/privesc/checklist.md`; use `skills/authz-context/refs/`. Write outputs to `<engagement>/privesc/`.
3. **Coverage:** copy your filled checklist into `<engagement>/privesc/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/privesc --out <engagement>/privesc` → fix + re-run until exit 0.
5. **Reviewer:** launch the `privesc-verify` subagent on `<engagement>/privesc`. Only `accepted` findings go to reporting.
