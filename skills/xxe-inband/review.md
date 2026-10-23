# In-Band XXE — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/xxe-inband --out <out_dir>
# Liveness only. Empty findings.json (ran, entities not resolved externally) is a PASS.

- [ ] A — XXE tests
  - [ ] A.1 `xxe_tests.jsonl` ≥1 record, each line valid JSON
- [ ] B — Findings
  - [ ] B.1 `findings.json` valid JSON (empty array → PASS)
- [ ] C — PoC (verify.md enforces when findings non-empty)
  - [ ] C.1 `poc/` (optional)
- [ ] D — Report
  - [ ] D.1 `report.md` non-zero; `curl_commands.sh` runnable
- [ ] E — Logs
  - [ ] E.1 `logs/` populated
- [ ] F — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "xxe-inband",
  "artifacts": [
    { "id": "A.1", "path": "xxe_tests.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "B.1", "path": "findings.json", "type": "json", "allow_empty_array": true, "schema": "skills/_contract/finding.schema.json" },
    { "id": "C.1", "path": "poc", "type": "dir", "required": false },
    { "id": "D.1", "path": "report.md", "type": "text" },
    { "id": "D.2", "path": "curl_commands.sh", "type": "text", "must_contain": "curl" },
    { "id": "E.1", "path": "logs", "type": "dir" }
  ]
}
```
