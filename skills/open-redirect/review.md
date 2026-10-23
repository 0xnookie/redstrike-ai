# Open Redirect — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/open-redirect --out <out_dir>
# Liveness only. Empty findings.json (ran, none redirect externally) is a PASS.

- [ ] A — Redirect params
  - [ ] A.1 `redirect_params.json` valid JSON
- [ ] B — Redirect tests
  - [ ] B.1 `redirect_tests.jsonl` ≥1 record, each line valid JSON
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
  "skill": "open-redirect",
  "artifacts": [
    { "id": "A.1", "path": "redirect_params.json", "type": "json", "allow_empty_array": true },
    { "id": "B.1", "path": "redirect_tests.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "C.1", "path": "findings.json", "type": "json", "allow_empty_array": true, "schema": "skills/_contract/finding.schema.json" },
    { "id": "D.1", "path": "poc", "type": "dir", "required": false },
    { "id": "E.1", "path": "report.md", "type": "text" },
    { "id": "E.2", "path": "curl_commands.sh", "type": "text", "must_contain": "curl" },
    { "id": "F.1", "path": "logs", "type": "dir" }
  ]
}
```
