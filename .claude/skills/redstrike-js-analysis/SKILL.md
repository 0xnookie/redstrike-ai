---
name: redstrike-js-analysis
description: Run Redstrike JS-analysis recon — endpoints, params, APIs, secrets, DOM sinks, libraries/tech — into the engagement dir. Feeds content-discovery and the XSS agents. Recon (review.md only, no reviewer).
---

Run the Redstrike **js-analysis** methodology (canonical spec: `skills/js-analysis/`).

1. **Scope:** honor `skills/_contract/roe-gate.md` + the engagement `scope.yaml` on every fetch.
2. **Execute:** follow `skills/js-analysis/SKILL.md`; work `skills/js-analysis/checklist.md` (mark `- [x]` only when a step's artifact exists); use `skills/js-analysis/refs/` + `skills/_contract/anti-automation-ladder.md`. Write all outputs to `<engagement>/js-analysis/`.
3. **Coverage:** copy your filled checklist into `<engagement>/js-analysis/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/js-analysis --out <engagement>/js-analysis` → fix any failed step, re-run until exit 0.
5. Recon skill — **no findings, no reviewer** (liveness only). Outputs feed `redstrike-xss-context`, content-discovery, and the vuln agents.
