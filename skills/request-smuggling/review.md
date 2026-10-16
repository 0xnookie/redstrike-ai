# HTTP Request Smuggling — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/request-smuggling --out <out_dir>
# Liveness only. Empty findings.json (ran, no desync) is a PASS.

- [ ] A — Chain fingerprint
  - [ ] A.1 `chain_fingerprint.json` valid JSON
- [ ] B — Desync tests
  - [ ] B.1 `desync_tests.jsonl` ≥1 record, each line valid JSON
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
  "skill": "request-smuggling",
  "artifacts": [
    { "id": "A.1", "path": "chain_fingerprint.json", "type": "json", "allow_empty_array": true },
    { "id": "B.1", "path": "desync_tests.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "C.1", "path": "findings.json", "type": "json", "allow_empty_array": true },
    { "id": "D.1", "path": "poc", "type": "dir", "required": false },
    { "id": "E.1", "path": "cleanup.md", "type": "text" },
    { "id": "F.1", "path": "report.md", "type": "text" },
    { "id": "G.1", "path": "logs", "type": "dir" }
  ]
}
```
