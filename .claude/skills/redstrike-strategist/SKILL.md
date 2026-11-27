---
name: redstrike-strategist
description: Run the Redstrike strategist / hunt-planner capability — read the post-recon state (coverage_ledger.json, surface_ledger.json, the *_context.json feeders, notebook.json, cve_intel.json) and emit a ranked hunt_plan.json (hunt queue + per-class depth budget + rationale) that ORDERS the orchestrator's pending-class loop. Re-invokable to re-rank the REMAINING queue as findings arrive. Tier-3 capability skill (review.md only, emits NO findings, writes NO ledger). ORDER + DEPTH-BUDGET only — it can never skip a class or lower the recall floor.
---

Run the Redstrike **strategist** / hunt-planner (canonical spec: `skills/strategist/`). TIER-3 capability service.

1. **Scope:** pure reasoning over on-disk state — NO network, NO target traffic. Honor `skills/_contract/roe-gate.md` + `scope.yaml`.
2. **Execute:** follow `skills/strategist/SKILL.md`; read the post-recon state (`coverage_ledger.json` = routed classes, `surface_ledger.json` = surface breadth, the `*_context.json` feeders, `notebook.json`, `cve_intel.json`, `scope.yaml`, `routing-map.json` `session_dependence` + the OPTIONAL `runtime/session_status.json`); reuse `scripts/escalation.py` (read-only) for each class's ladder floor; work `skills/strategist/checklist.md`. Emit `<engagement>/hunt_plan.json` (schema `skills/_contract/hunt_plan.schema.json`) + `summary.md` + `logs/`.
3. **ABSOLUTE INVARIANT:** ORDER + per-class DEPTH-BUDGET only. NEVER mark a class `skipped`, NEVER write any ledger (`coverage.py` stays the sole ledger owner), NEVER lower the recall floor. A mis-rank wastes budget at worst — it can never create a silent miss.
4. **Coverage:** copy your filled checklist into `<engagement>/strategist/checklist.md`.
5. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/strategist --out <engagement>` → fix + re-run until exit 0.
6. Capability service — **no findings, no reviewer** (`review.md` only). Re-invoke after each wave to re-rank the REMAINING (not-yet-`done`) queue. Feeds the `redstrike` orchestrator's §2b pending-class loop.
