# Reporting — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/reporting --out <out_dir>
# Terminal aggregator → liveness only, no verify.md (findings verified upstream).
# An engagement with zero accepted findings is a valid PASS (empty consolidated array + a report saying so).

- [ ] A — Consolidated findings
  - [ ] A.1 `findings_consolidated.json` valid JSON (empty array = no accepted findings → still PASS)
- [ ] B — Report
  - [ ] B.1 `report.md` non-zero (executive summary + findings, or a clean "no confirmed findings")
- [ ] C — Summary
  - [ ] C.1 `summary.md` non-zero
- [ ] D — Logs
  - [ ] D.1 `logs/` populated
- [ ] E — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "reporting",
  "artifacts": [
    { "id": "A.1", "path": "findings_consolidated.json", "type": "json", "allow_empty_array": true },
    { "id": "B.1", "path": "report.md", "type": "text" },
    { "id": "C.1", "path": "summary.md", "type": "text" },
    { "id": "D.1", "path": "logs", "type": "dir" }
  ]
}
```
