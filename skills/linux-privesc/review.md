# Linux Privesc — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/linux-privesc --out <out_dir>
# Liveness only. Empty findings.json (ran, no privesc vector) is a PASS.

- [ ] A — Enumeration
  - [ ] A.1 `enum.json` valid JSON, non-empty
- [ ] B — Privesc tests
  - [ ] B.1 `privesc_tests.jsonl` ≥1 record, each line valid JSON
- [ ] C — Findings
  - [ ] C.1 `findings.json` valid JSON (empty array → PASS)
- [ ] D — PoC (verify.md enforces when findings non-empty)
  - [ ] D.1 `poc/` (optional)
- [ ] E — Cleanup
  - [ ] E.1 `cleanup.md` non-zero
- [ ] F — Report
  - [ ] F.1 `report.md` non-zero
- [ ] G — Logs
  - [ ] G.1 `logs/` populated
- [ ] H — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "linux-privesc",
  "artifacts": [
    { "id": "A.1", "path": "enum.json", "type": "json" },
    { "id": "B.1", "path": "privesc_tests.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "C.1", "path": "findings.json", "type": "json", "allow_empty_array": true },
    { "id": "D.1", "path": "poc", "type": "dir", "required": false },
    { "id": "E.1", "path": "cleanup.md", "type": "text" },
    { "id": "F.1", "path": "report.md", "type": "text" },
    { "id": "G.1", "path": "logs", "type": "dir" }
  ]
}
```
