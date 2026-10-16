---
name: redstrike-host-header
description: Run the Redstrike host-header-injection hunt (executor) — attacker host into reset links / redirects / cache keys — then gate and hand off to the host-header-verify reviewer agent.
---

Run the Redstrike **host-header** methodology (canonical spec: `skills/host-header/`).

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`; use a test account for reset flows — never trigger resets for real users.
2. **Execute:** follow `skills/host-header/SKILL.md`; consume `skills/js-analysis/` reset/email/redirect flows; work `skills/host-header/checklist.md`. Write outputs to `<engagement>/host-header/`.
3. **Coverage:** copy your filled checklist into `<engagement>/host-header/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/host-header --out <engagement>/host-header` → fix + re-run until exit 0.
5. **Reviewer:** launch the `host-header-verify` subagent on `<engagement>/host-header`. Only `accepted` findings go to reporting.
