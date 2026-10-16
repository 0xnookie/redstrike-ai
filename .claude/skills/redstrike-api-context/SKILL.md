---
name: redstrike-api-context
description: Run the Redstrike API context feeder — map REST/GraphQL endpoints + object/role/field surface into api_context.json for bola-bfla/graphql. Needs >=2 identities. Recon feeder (review.md only). No DoS.
---

Run the Redstrike **api-context** feeder (canonical spec: `skills/api-context/`).

1. **Scope:** honor `skills/_contract/roe-gate.md` + `scope.yaml`. Enumeration/introspection only — **no deep-nesting/batched DoS**. Use TEST accounts.
2. **Execute:** follow `skills/api-context/SKILL.md`; needs `auth.env` with **≥2 identities**; consume `skills/js-analysis/apis.json` + any OpenAPI/GraphQL spec; work `skills/api-context/checklist.md`; use `skills/api-context/refs/`. Write outputs to `<engagement>/api-context/` — key artifact `api_context.json` (validate against `skills/_contract/api_context.schema.json`).
3. **Coverage:** copy your filled checklist into `<engagement>/api-context/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/api-context --out <engagement>/api-context` → fix + re-run until exit 0.
5. Recon feeder — **no findings, no reviewer**. `api_context.json` feeds `redstrike-bola-bfla | graphql`.
