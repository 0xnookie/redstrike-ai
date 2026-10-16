---
name: redstrike-parameter-optimization
description: Run the Redstrike parameter-optimization service — model a target agent's WAF/filter, generate optimized benign payload variants, mine params, and derive a safe throughput profile for that agent to re-run. Service skill (review.md only, no findings).
---

Run the Redstrike **parameter-optimization** service (canonical spec: `skills/parameter-optimization/`). TIER-3.

1. **Scope:** honor `skills/_contract/roe-gate.md` + `scope.yaml`. Benign variants only (it optimizes EXISTING benign test payloads — never weaponizes); throughput tuning exists to STAY UNDER rate limits, not to flood.
2. **Execute:** follow `skills/parameter-optimization/SKILL.md`; ingest a Tier-2 agent's `payloads_tried.jsonl` (+ WAF/block signals) + that agent's `refs/`; work `skills/parameter-optimization/checklist.md`. Write outputs to `<engagement>/parameter-optimization/` (`optimized_payloads.jsonl`, `mined_params.txt`).
3. **Coverage:** copy your filled checklist into `<engagement>/parameter-optimization/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/parameter-optimization --out <engagement>/parameter-optimization` → fix + re-run until exit 0.
5. Service — **no findings, no reviewer**. Hand the optimized sets back to the target Tier-2 agent, which applies its own safety rules on re-run.
