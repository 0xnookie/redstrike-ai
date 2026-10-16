---
name: redstrike-reporting
description: Run the Redstrike reporting aggregator — collect every skill's ACCEPTED findings, de-dupe, normalize CVSS, and assemble the client report (executive summary + risk-ordered writeups + consolidated JSON). Terminal skill (review.md only).
---

Run the Redstrike **reporting** methodology (canonical spec: `skills/reporting/`).

1. **Scope:** read the engagement `scope.yaml` for metadata (client, dates, scope). Report only `accepted` findings — never `rejected`/`needs-evidence` as confirmed; keep redacted secrets redacted.
2. **Execute:** follow `skills/reporting/SKILL.md`; collect every `<engagement>/<skill>/findings.json`, filter to `review.verdict == "accepted"`, de-dupe across agents, normalize CVSS; use `skills/reporting/refs/report_template.md`. Write outputs to `<engagement>/report/` (`report.md`, `findings_consolidated.json`, `summary.md`).
3. **Coverage:** copy your filled checklist into `<engagement>/report/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/reporting --out <engagement>/report` → fix + re-run until exit 0.
5. Terminal — **no reviewer** (findings were verified upstream). Deliver `report.md` to the client through the agreed channel; the engagement dir is the audit trail.
