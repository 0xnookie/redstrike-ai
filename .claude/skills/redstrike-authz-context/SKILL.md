---
name: redstrike-authz-context
description: Run the Redstrike authorization context feeder — build the object-reference list + identity/role × endpoint matrix + mass-assign candidates into authz_context.json for idor/privesc. Needs >=2 identities. Recon feeder (review.md only).
---

Run the Redstrike **authz-context** feeder (canonical spec: `skills/authz-context/`).

1. **Scope:** honor `skills/_contract/roe-gate.md` + `scope.yaml`. Enumeration only — don't access another account's data while mapping. Use TEST accounts.
2. **Execute:** follow `skills/authz-context/SKILL.md`; needs `auth.env` with **≥2 identities + roles** (+admin if available); consume `skills/js-analysis/` endpoints/params; work `skills/authz-context/checklist.md`; use `skills/authz-context/refs/`. Write outputs to `<engagement>/authz-context/` — key artifact `authz_context.json` (validate against `skills/_contract/authz_context.schema.json`).
3. **Coverage:** copy your filled checklist into `<engagement>/authz-context/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/authz-context --out <engagement>/authz-context` → fix + re-run until exit 0.
5. Recon feeder — **no findings, no reviewer**. `authz_context.json` feeds `redstrike-idor` + `redstrike-privesc`.
