# Stored XSS — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/xss-stored --out <out_dir>
# Liveness only. Empty findings.json (ran, nothing stored-executed) is a PASS here;
# whether a finding is REAL — and whether it fired for a DIFFERENT user — is verify.md's job.

- [ ] A — Candidates
  - [ ] A.1 `stored_candidates.json` valid JSON
- [ ] B — Render map
  - [ ] B.1 `render_map.json` valid JSON
- [ ] C — Tracers
  - [ ] C.1 `tracers.jsonl` ≥1 record, each line valid JSON
- [ ] D — Payload/sanitizer probing
  - [ ] D.1 `payloads_tried.jsonl` ≥1 record, each line valid JSON
- [ ] E — Findings
  - [ ] E.1 `findings.json` valid JSON (empty array = ran, nothing found → PASS)
- [ ] F — PoC (present when findings non-empty — enforced semantically by verify.md)
  - [ ] F.1 `poc/` directory (optional at this altitude)
- [ ] G — Cleanup
  - [ ] G.1 `cleanup.md` non-zero (records stored artifacts + removal, even if "none left")
- [ ] H — Report
  - [ ] H.1 `report.md` non-zero; `curl_commands.sh` runnable
- [ ] I — Logs
  - [ ] I.1 `logs/` populated
- [ ] J — /REVIEW SKILL → any unchecked ⇒ re-run that step

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "xss-stored",
  "artifacts": [
    { "id": "A.1", "path": "stored_candidates.json", "type": "json", "allow_empty_array": true },
    { "id": "B.1", "path": "render_map.json", "type": "json", "allow_empty_array": true },
    { "id": "C.1", "path": "tracers.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "D.1", "path": "payloads_tried.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "E.1", "path": "findings.json", "type": "json", "allow_empty_array": true },
    { "id": "F.1", "path": "poc", "type": "dir", "required": false },
    { "id": "G.1", "path": "cleanup.md", "type": "text" },
    { "id": "H.1", "path": "report.md", "type": "text" },
    { "id": "H.2", "path": "curl_commands.sh", "type": "text", "must_contain": "curl" },
    { "id": "I.1", "path": "logs", "type": "dir" }
  ]
}
```
