---
name: redstrike-ssrf-context
description: Run the Redstrike SSRF context feeder — map URL-fetching sinks + fetch behavior into ssrf_context.json for the SSRF variant agents (inband/blind/cloud). Recon feeder (review.md only).
---

Run the Redstrike **ssrf-context** feeder (canonical spec: `skills/ssrf-context/`).

1. **Scope:** honor `skills/_contract/roe-gate.md` + `scope.yaml` on every OOB probe (benign only).
2. **Execute:** follow `skills/ssrf-context/SKILL.md`; consume `skills/js-analysis/` params/endpoints; work `skills/ssrf-context/checklist.md`; use `skills/ssrf-context/refs/`. Write outputs to `<engagement>/ssrf-context/` — the key artifact is `ssrf_context.json` (validate against `skills/_contract/ssrf_context.schema.json`).
3. **Coverage:** copy your filled checklist into `<engagement>/ssrf-context/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/ssrf-context --out <engagement>/ssrf-context` → fix + re-run until exit 0.
5. Recon feeder — **no findings, no reviewer**. `ssrf_context.json` feeds `redstrike-ssrf-inband|blind|cloud`.
