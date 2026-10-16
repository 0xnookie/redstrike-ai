---
name: redstrike-auth-bypass
description: Run the Redstrike authentication-bypass hunt (executor) — forced browsing / response tampering / 2FA skip / fixation / reset flaws — then gate and hand off to the auth-bypass-verify reviewer agent.
---

Run the Redstrike **auth-bypass** methodology (canonical spec: `skills/auth-bypass/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. TEST accounts only; **no real brute-force** (few rate-limited attempts, never lock out real users); reset/MFA flows **approval-gated**.
2. **Execute:** follow `skills/auth-bypass/SKILL.md`; consume `<engagement>/auth-context/auth_context.json` (flows, session); work `skills/auth-bypass/checklist.md`; use `skills/auth-context/refs/`. Write outputs to `<engagement>/auth-bypass/`. (Reset host-poisoning → `redstrike-host-header`.)
3. **Coverage:** copy your filled checklist into `<engagement>/auth-bypass/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/auth-bypass --out <engagement>/auth-bypass` → fix + re-run until exit 0.
5. **Reviewer:** launch the `auth-bypass-verify` subagent on `<engagement>/auth-bypass`. Only `accepted` findings go to reporting.
