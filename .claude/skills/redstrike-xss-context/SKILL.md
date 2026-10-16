---
name: redstrike-xss-context
description: Run the Redstrike XSS context feeder — map the injection surface, reflection/persistence, CSP, and DOM source->sink flows into xss_context.json for the XSS variant agents. Recon feeder (review.md only).
---

Run the Redstrike **xss-context** feeder (canonical spec: `skills/xss-context/`).

1. **Scope:** honor `skills/_contract/roe-gate.md` + `scope.yaml` on every probe (benign markers only).
2. **Execute:** follow `skills/xss-context/SKILL.md`; work `skills/xss-context/checklist.md`; consume `skills/js-analysis/` outputs. Write all outputs to `<engagement>/xss-context/` — the key artifact is `xss_context.json` (validate against `skills/_contract/xss_context.schema.json`).
3. **Coverage:** copy your filled checklist into `<engagement>/xss-context/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/xss-context --out <engagement>/xss-context` → fix + re-run until exit 0.
5. Recon feeder — **no findings, no reviewer**. `xss_context.json` feeds `redstrike-xss-reflected|stored|dom|blind`.
