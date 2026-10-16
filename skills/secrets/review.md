# Secrets Validation — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/secrets --out <out_dir>
# Liveness only. Empty candidates/findings (js-analysis found no secrets) is a PASS.
# validations.jsonl may be empty if there were no candidates to validate.

- [ ] A — Candidates
  - [ ] A.1 `secret_candidates.json` valid JSON (empty array → PASS)
- [ ] B — Validations
  - [ ] B.1 `validations.jsonl` valid JSONL (may be empty if no candidates)
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
  "skill": "secrets",
  "artifacts": [
    { "id": "A.1", "path": "secret_candidates.json", "type": "json", "allow_empty_array": true },
    { "id": "B.1", "path": "validations.jsonl", "type": "jsonl", "allow_empty": true },
    { "id": "C.1", "path": "findings.json", "type": "json", "allow_empty_array": true },
    { "id": "D.1", "path": "report.md", "type": "text" },
    { "id": "E.1", "path": "logs", "type": "dir" }
  ]
}
```
