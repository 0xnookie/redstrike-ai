# Subdomain Takeover — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/subdomain-takeover --out <out_dir>
# Liveness only. Empty findings.json (ran, no dangling records) is a PASS.

- [ ] A — DNS records
  - [ ] A.1 `dns_records.json` valid JSON
- [ ] B — Candidates
  - [ ] B.1 `takeover_candidates.jsonl` ≥1 record, each line valid JSON
- [ ] C — Findings
  - [ ] C.1 `findings.json` valid JSON (empty array → PASS)
- [ ] D — PoC (verify.md enforces when findings non-empty)
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
  "skill": "subdomain-takeover",
  "artifacts": [
    { "id": "A.1", "path": "dns_records.json", "type": "json", "allow_empty_array": true },
    { "id": "B.1", "path": "takeover_candidates.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "C.1", "path": "findings.json", "type": "json", "allow_empty_array": true },
    { "id": "D.1", "path": "poc", "type": "dir", "required": false },
    { "id": "E.1", "path": "report.md", "type": "text" },
    { "id": "F.1", "path": "logs", "type": "dir" }
  ]
}
```
