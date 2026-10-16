---
name: redstrike-bola-bfla
description: Run the Redstrike BOLA/BFLA hunt (executor) — API object/function-level authz + excessive data + mass assignment, with two identities — then gate and hand off to the bola-bfla-verify reviewer agent.
---

Run the Redstrike **bola-bfla** methodology (canonical spec: `skills/bola-bfla/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. TWO TEST accounts (never real-user data); BFLA privileged actions **approval-gated** + benign/reversible.
2. **Execute:** follow `skills/bola-bfla/SKILL.md`; consume `<engagement>/api-context/api_context.json` (endpoints, object params, roles, fields) + `auth.env` (≥2 identities); work `skills/bola-bfla/checklist.md`; use `skills/api-context/refs/`. Write outputs to `<engagement>/bola-bfla/`. De-dupe with `idor`/`privesc` at reporting.
3. **Coverage:** copy your filled checklist into `<engagement>/bola-bfla/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/bola-bfla --out <engagement>/bola-bfla` → fix + re-run until exit 0.
5. **Reviewer:** launch the `bola-bfla-verify` subagent on `<engagement>/bola-bfla`. Only `accepted` findings go to reporting.
