# Security Headers — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/security-headers --out <out_dir>
# Liveness only. Empty findings.json (ran, headers adequate) is a PASS.

- [ ] A — Headers
  - [ ] A.1 `headers.json` valid JSON
- [ ] B — Assessment
  - [ ] B.1 `assessment.json` valid JSON
- [ ] C — Findings
  - [ ] C.1 `findings.json` valid JSON (empty array → PASS)
- [ ] D — Report
  - [ ] D.1 `report.md` non-zero
- [ ] E — Logs
  - [ ] E.1 `logs/` populated
- [ ] F — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "security-headers",
  "artifacts": [
    { "id": "A.1", "path": "headers.json", "type": "json" },
    { "id": "B.1", "path": "assessment.json", "type": "json" },
    { "id": "C.1", "path": "findings.json", "type": "json", "allow_empty_array": true },
    { "id": "D.1", "path": "report.md", "type": "text" },
    { "id": "E.1", "path": "logs", "type": "dir" }
  ]
}
```
