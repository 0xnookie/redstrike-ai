# Business Logic — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/business-logic --out <out_dir>
# Liveness only. Empty findings.json (ran, invariants held) is a PASS.

- [ ] A — Workflow model
  - [ ] A.1 `workflow_model.md` non-zero
- [ ] B — Invariants
  - [ ] B.1 `invariants.json` valid JSON, non-empty
- [ ] C — Abuse tests
  - [ ] C.1 `abuse_tests.jsonl` ≥1 record, each line valid JSON
- [ ] D — Findings
  - [ ] D.1 `findings.json` valid JSON (empty array → PASS)
- [ ] E — PoC (verify.md enforces when findings non-empty)
  - [ ] E.1 `poc/` (optional)
- [ ] F — Report
  - [ ] F.1 `report.md` non-zero
- [ ] G — Logs
  - [ ] G.1 `logs/` populated
- [ ] H — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "business-logic",
  "artifacts": [
    { "id": "A.1", "path": "workflow_model.md", "type": "text" },
    { "id": "B.1", "path": "invariants.json", "type": "json" },
    { "id": "C.1", "path": "abuse_tests.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "D.1", "path": "findings.json", "type": "json", "allow_empty_array": true, "schema": "skills/_contract/finding.schema.json" },
    { "id": "E.1", "path": "poc", "type": "dir", "required": false },
    { "id": "F.1", "path": "report.md", "type": "text" },
    { "id": "G.1", "path": "logs", "type": "dir" }
  ]
}
```
