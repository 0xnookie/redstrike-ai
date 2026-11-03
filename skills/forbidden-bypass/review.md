# Forbidden / 403 Bypass — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/forbidden-bypass --out <out_dir>
# Liveness only. Empty findings.json (ran, no restriction bypassed) is a PASS.

- [ ] A — Restricted endpoints
  - [ ] A.1 `restricted_endpoints.jsonl` ≥1 record (baseline 401/403 inventory), each line valid JSON
- [ ] B — Bypass tests
  - [ ] B.1 `bypass_tests.jsonl` ≥1 record, each line valid JSON
- [ ] C — Findings
  - [ ] C.1 `findings.json` valid JSON (empty array → PASS)
- [ ] D — PoC (verify.md enforces when findings non-empty)
  - [ ] D.1 `poc/` (optional)
- [ ] E — Report
  - [ ] E.1 `report.md` non-zero; `curl_commands.sh` runnable
- [ ] F — Logs
  - [ ] F.1 `logs/` populated
- [ ] G — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "forbidden-bypass",
  "artifacts": [
    { "id": "A.1", "path": "restricted_endpoints.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "B.1", "path": "bypass_tests.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "C.1", "path": "findings.json", "type": "json", "allow_empty_array": true, "schema": "skills/_contract/finding.schema.json" },
    { "id": "D.1", "path": "poc", "type": "dir", "required": false },
    { "id": "E.1", "path": "report.md", "type": "text" },
    { "id": "E.2", "path": "curl_commands.sh", "type": "text", "must_contain": "curl" },
    { "id": "F.1", "path": "logs", "type": "dir" }
  ]
}
```
