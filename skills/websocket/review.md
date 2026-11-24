# WebSocket (CSWSH / message-layer / socket authz) — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/websocket --out <out_dir>
# Liveness only. callbacks.jsonl may be empty (a break is usually proven by a cross-origin read / before-after state, not an OOB hit). Empty findings.json is a PASS.

- [ ] A — WS tests
  - [ ] A.1 `ws_tests.jsonl` ≥1 record, each line valid JSON
- [ ] B — Callbacks
  - [ ] B.1 `callbacks.jsonl` valid JSONL (MAY be empty)
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
  "skill": "websocket",
  "artifacts": [
    { "id": "A.1", "path": "ws_tests.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "B.1", "path": "callbacks.jsonl", "type": "jsonl", "allow_empty": true },
    { "id": "C.1", "path": "findings.json", "type": "json", "allow_empty_array": true, "schema": "skills/_contract/finding.schema.json" },
    { "id": "D.1", "path": "poc", "type": "dir", "required": false },
    { "id": "E.1", "path": "report.md", "type": "text" },
    { "id": "F.1", "path": "logs", "type": "dir" }
  ]
}
```
