# Blind XXE — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/xxe-blind --out <out_dir>
# ASYNC + liveness only. callbacks.jsonl may be empty. Empty findings.json is a PASS.

- [ ] A — OOB config
  - [ ] A.1 `oob_config.json` valid JSON
- [ ] B — XXE tests
  - [ ] B.1 `xxe_tests.jsonl` ≥1 record, each line valid JSON
- [ ] C — Callbacks
  - [ ] C.1 `callbacks.jsonl` valid JSONL (MAY be empty — async)
- [ ] D — Findings
  - [ ] D.1 `findings.json` valid JSON (empty array → PASS)
- [ ] E — PoC (verify.md enforces when findings non-empty)
  - [ ] E.1 `poc/` (optional)
- [ ] F — Report
  - [ ] F.1 `report.md` non-zero; `curl_commands.sh` runnable
- [ ] G — Logs
  - [ ] G.1 `logs/` populated
- [ ] H — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "xxe-blind",
  "artifacts": [
    { "id": "A.1", "path": "oob_config.json", "type": "json" },
    { "id": "B.1", "path": "xxe_tests.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "C.1", "path": "callbacks.jsonl", "type": "jsonl", "allow_empty": true },
    { "id": "D.1", "path": "findings.json", "type": "json", "allow_empty_array": true, "schema": "skills/_contract/finding.schema.json" },
    { "id": "E.1", "path": "poc", "type": "dir", "required": false },
    { "id": "F.1", "path": "report.md", "type": "text" },
    { "id": "F.2", "path": "curl_commands.sh", "type": "text", "must_contain": "curl" },
    { "id": "G.1", "path": "logs", "type": "dir" }
  ]
}
```
