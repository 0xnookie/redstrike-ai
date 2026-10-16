# Upload-to-RCE — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/upload-rce --out <out_dir>
# Liveness only. Empty findings.json (ran, uploads safe) is a PASS.

- [ ] A — Upload tests
  - [ ] A.1 `upload_tests.jsonl` ≥1 record, each line valid JSON
- [ ] B — Findings
  - [ ] B.1 `findings.json` valid JSON (empty array → PASS)
- [ ] C — PoC (verify.md enforces when findings non-empty)
  - [ ] C.1 `poc/` (optional)
- [ ] D — Cleanup
  - [ ] D.1 `cleanup.md` non-zero (uploaded artifacts recorded + removed)
- [ ] E — Report
  - [ ] E.1 `report.md` non-zero; `curl_commands.sh` runnable
- [ ] F — Logs
  - [ ] F.1 `logs/` populated
- [ ] G — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "upload-rce",
  "artifacts": [
    { "id": "A.1", "path": "upload_tests.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "B.1", "path": "findings.json", "type": "json", "allow_empty_array": true },
    { "id": "C.1", "path": "poc", "type": "dir", "required": false },
    { "id": "D.1", "path": "cleanup.md", "type": "text" },
    { "id": "E.1", "path": "report.md", "type": "text" },
    { "id": "E.2", "path": "curl_commands.sh", "type": "text", "must_contain": "curl" },
    { "id": "F.1", "path": "logs", "type": "dir" }
  ]
}
```
