---
name: redstrike-jwt
description: Run the Redstrike JWT-attack hunt (executor) — alg:none / weak secret / key confusion / claim tamper, confirm a forged token is accepted — then gate and hand off to the jwt-verify reviewer agent.
---

Run the Redstrike **jwt** methodology (canonical spec: `skills/jwt/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. Forge tokens for a TEST account only; offline cracking only (no online brute); don't impersonate a real user's data; **approval-gated**.
2. **Execute:** follow `skills/jwt/SKILL.md`; consume `<engagement>/auth-context/auth_context.json` (session.jwt) + `auth.env` (a valid token); work `skills/jwt/checklist.md`; use `skills/auth-context/refs/`. Write outputs to `<engagement>/jwt/`.
3. **Coverage:** copy your filled checklist into `<engagement>/jwt/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/jwt --out <engagement>/jwt` → fix + re-run until exit 0.
5. **Reviewer:** launch the `jwt-verify` subagent on `<engagement>/jwt`. Only `accepted` findings go to reporting.
