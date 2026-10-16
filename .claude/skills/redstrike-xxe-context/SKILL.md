---
name: redstrike-xxe-context
description: Run the Redstrike XXE context feeder — map XML-parsing sinks (SOAP, XML APIs, SVG/DOCX uploads, SAML) + entity-resolution behavior into xxe_context.json for xxe-inband/blind. Recon feeder (review.md only). Benign internal entities; no DoS.
---

Run the Redstrike **xxe-context** feeder (canonical spec: `skills/xxe-context/`).

1. **Scope:** honor `skills/_contract/roe-gate.md` + `scope.yaml`. Benign INTERNAL entities for detection only — no external file reads / SSRF here; **never** entity-expansion DoS.
2. **Execute:** follow `skills/xxe-context/SKILL.md`; consume `skills/js-analysis/` endpoints/apis (XML content-types, uploads); work `skills/xxe-context/checklist.md`; use `skills/xxe-context/refs/`. Write outputs to `<engagement>/xxe-context/` — key artifact `xxe_context.json` (validate against `skills/_contract/xxe_context.schema.json`).
3. **Coverage:** copy your filled checklist into `<engagement>/xxe-context/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/xxe-context --out <engagement>/xxe-context` → fix + re-run until exit 0.
5. Recon feeder — **no findings, no reviewer**. `xxe_context.json` feeds `redstrike-xxe-inband | xxe-blind`.
