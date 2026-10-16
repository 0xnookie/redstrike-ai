---
name: redstrike-auth-context
description: Run the Redstrike auth context feeder — map session mechanism (cookie/JWT), flows (login/reset/MFA/OAuth), and OAuth config into auth_context.json for auth-bypass/jwt/oauth. Recon feeder (review.md only). Inspection only.
---

Run the Redstrike **auth-context** feeder (canonical spec: `skills/auth-context/`).

1. **Scope:** honor `skills/_contract/roe-gate.md` + `scope.yaml`. Inspection only (decode your OWN token; benign fixation/logout checks) — no credential attacks here. Use a TEST account.
2. **Execute:** follow `skills/auth-context/SKILL.md`; consume `skills/js-analysis/` + `auth.env`; work `skills/auth-context/checklist.md`; use `skills/auth-context/refs/`. Write outputs to `<engagement>/auth-context/` — key artifact `auth_context.json` (validate against `skills/_contract/auth_context.schema.json`).
3. **Coverage:** copy your filled checklist into `<engagement>/auth-context/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/auth-context --out <engagement>/auth-context` → fix + re-run until exit 0.
5. Recon feeder — **no findings, no reviewer**. `auth_context.json` feeds `redstrike-auth-bypass | jwt | oauth`.
