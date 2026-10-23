# CSRF — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/csrf --out <out_dir>
# Liveness only. Empty findings.json (ran, all requests protected) is a PASS.

- [ ] A — State-changing requests
  - [ ] A.1 `state_changing_requests.json` valid JSON
- [ ] B — Defense matrix
  - [ ] B.1 `defense_matrix.json` valid JSON
- [ ] C — Findings
  - [ ] C.1 `findings.json` valid JSON (empty array → PASS)
- [ ] D — PoC (present when findings non-empty — verify.md enforces)
  - [ ] D.1 `poc/` (optional)
- [ ] E — Report
  - [ ] E.1 `report.md` non-zero
- [ ] F — Logs
  - [ ] F.1 `logs/` populated
- [ ] G — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "csrf",
  "artifacts": [
    { "id": "A.1", "path": "state_changing_requests.json", "type": "json", "allow_empty_array": true },
    { "id": "B.1", "path": "defense_matrix.json", "type": "json", "allow_empty_array": true },
    { "id": "C.1", "path": "findings.json", "type": "json", "allow_empty_array": true, "schema": "skills/_contract/finding.schema.json" },
    { "id": "D.1", "path": "poc", "type": "dir", "required": false },
    { "id": "E.1", "path": "report.md", "type": "text" },
    { "id": "F.1", "path": "logs", "type": "dir" }
  ]
}
```
