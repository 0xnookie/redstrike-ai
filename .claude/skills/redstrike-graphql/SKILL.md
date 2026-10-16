---
name: redstrike-graphql
description: Run the Redstrike GraphQL hunt (executor) — introspection / field-authz / node-IDOR / arg-injection, DoS feasibility only — then gate and hand off to the graphql-verify reviewer agent.
---

Run the Redstrike **graphql** methodology (canonical spec: `skills/graphql/`).

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Never run a DoS query** (deep nesting / alias / batching) — assess + report feasibility only. Node-IDOR uses TEST accounts.
2. **Execute:** follow `skills/graphql/SKILL.md`; consume `<engagement>/api-context/api_context.json` (graphql schema/ops) + `auth.env` (≥2 identities); work `skills/graphql/checklist.md`; use `skills/api-context/refs/`. Write outputs to `<engagement>/graphql/`. Arg-injection confirmation hands off to `redstrike-injection-context`/`sqli-*`.
3. **Coverage:** copy your filled checklist into `<engagement>/graphql/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/graphql --out <engagement>/graphql` → fix + re-run until exit 0.
5. **Reviewer:** launch the `graphql-verify` subagent on `<engagement>/graphql`. Only `accepted` findings go to reporting.
