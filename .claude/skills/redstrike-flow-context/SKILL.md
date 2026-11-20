---
name: redstrike-flow-context
description: Run the Redstrike flow context feeder — build the structured app state model (states → actions → transitions → guards → invariants, keyed to identity/role) into flow_context.json for business-logic/race-condition/auth-bypass/idor and the browser-exploit navigation plan. Needs >=2 identities. Recon feeder (review.md only).
---

Run the Redstrike **flow-context** feeder (canonical spec: `skills/flow-context/`).

1. **Scope:** honor `skills/_contract/roe-gate.md` + `scope.yaml`. Mapping/crawl only — don't break an invariant or cross an account while modeling. Use TEST accounts; keep state changes reversible.
2. **Execute:** follow `skills/flow-context/SKILL.md`; needs `auth.env` with **≥2 identities + roles** (+admin if available); consume `skills/content-discovery/` flows + `skills/js-analysis/` endpoints/params; work `skills/flow-context/checklist.md`; use `skills/flow-context/refs/`. Write outputs to `<engagement>/flow-context/` — key artifact `flow_context.json` (validate against `skills/_contract/flow_context.schema.json`).
3. **Coverage:** copy your filled checklist into `<engagement>/flow-context/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/flow-context --out <engagement>/flow-context` → fix + re-run until exit 0.
5. Recon feeder — **no findings, no reviewer**. `flow_context.json` feeds `redstrike-business-logic` + `redstrike-race-condition` + `redstrike-auth-bypass` + `redstrike-idor`.
