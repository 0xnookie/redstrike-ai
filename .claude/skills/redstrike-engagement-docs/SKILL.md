---
name: redstrike-engagement-docs
description: Write the full engagement document suite — Rules of Engagement (RoE) at the start, and the formal penetration test report + attestation letter + retest template at the end — from scope.yaml and the accepted findings. Invoke when the user asks to "write the report", "write the RoE / rules of engagement", "produce the pentest report", or "create the engagement documents". Documentation skill (review.md only).
---

Run the Redstrike **engagement-docs** methodology (canonical spec: `skills/engagement-docs/`).

1. **Mode + scope:** read the engagement `scope.yaml` for metadata (client, dates, scope, contacts, authorization). **Pre-engagement** → write the RoE. **Post-engagement** → write the full report + attestation + retest from the ACCEPTED findings. Factual + accepted-findings-only; keep redacted secrets redacted; never fabricate authorization or inflate severity. Deliverables are DRAFTS for a human to finalize + sign.
2. **Execute:** follow `skills/engagement-docs/SKILL.md`; consume `scope.yaml` + `<engagement>/report/findings_consolidated.json` (from `redstrike-reporting`); use `skills/engagement-docs/refs/doc_templates.md`. Write outputs to `<engagement>/docs/` (`RoE.md`, `report.md`, `attestation.md`, `retest.md`).
3. **Coverage:** copy your filled checklist into `<engagement>/docs/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/engagement-docs --out <engagement>/docs` → fix + re-run until exit 0.
5. Documentation skill — **no findings, no reviewer**. Deliver the suite to the client through the agreed channel; the engagement dir is the audit trail.
