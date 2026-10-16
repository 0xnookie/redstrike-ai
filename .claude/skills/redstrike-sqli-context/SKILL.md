---
name: redstrike-sqli-context
description: Run the Redstrike SQLi context feeder — map injectable params + query context + DBMS + error visibility into sqli_context.json for the SQLi variant agents. Recon feeder (review.md only). SELECT-safe probes only.
---

Run the Redstrike **sqli-context** feeder (canonical spec: `skills/sqli-context/`).

1. **Scope:** honor `skills/_contract/roe-gate.md` + `scope.yaml`. Benign, SELECT-safe probes only — NEVER stacked/destructive queries.
2. **Execute:** follow `skills/sqli-context/SKILL.md`; consume `skills/js-analysis/` params; work `skills/sqli-context/checklist.md`; use `skills/sqli-context/refs/`. Write outputs to `<engagement>/sqli-context/` — key artifact `sqli_context.json` (validate against `skills/_contract/sqli_context.schema.json`).
3. **Coverage:** copy your filled checklist into `<engagement>/sqli-context/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/sqli-context --out <engagement>/sqli-context` → fix + re-run until exit 0.
5. Recon feeder — **no findings, no reviewer**. `sqli_context.json` feeds `redstrike-sqli-inband|blind`.
