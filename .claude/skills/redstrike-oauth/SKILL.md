---
name: redstrike-oauth
description: Run the Redstrike OAuth/OIDC hunt (executor) — redirect_uri manipulation / state-CSRF / code reuse / PKCE / id_token validation to leak a code/token or take over an account — then gate and hand off to the oauth-verify reviewer agent.
---

Run the Redstrike **oauth** methodology (canonical spec: `skills/oauth/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. TEST accounts for attacker + victim; code/token leak goes to YOUR OOB host only; never capture a real user's token; **approval-gated**.
2. **Execute:** follow `skills/oauth/SKILL.md`; consume `<engagement>/auth-context/auth_context.json` (oauth config); work `skills/oauth/checklist.md`; use `skills/auth-context/refs/`. Write outputs to `<engagement>/oauth/`. (redirect_uri bypass ↔ `redstrike-open-redirect`.)
3. **Coverage:** copy your filled checklist into `<engagement>/oauth/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/oauth --out <engagement>/oauth` → fix + re-run until exit 0.
5. **Reviewer:** launch the `oauth-verify` subagent on `<engagement>/oauth`. Only `accepted` findings go to reporting.
