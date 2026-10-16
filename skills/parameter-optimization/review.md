# Parameter Optimization — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/parameter-optimization --out <out_dir>
# Service skill → liveness only, no verify.md (emits no findings).

- [ ] A — Filter analysis
  - [ ] A.1 `filter_analysis.json` valid JSON
- [ ] B — Optimized payloads
  - [ ] B.1 `optimized_payloads.jsonl` ≥1 record, each line valid JSON
- [ ] C — Mined params
  - [ ] C.1 `mined_params.txt` non-zero
- [ ] D — Summary
  - [ ] D.1 `summary.md` non-zero
- [ ] E — Logs
  - [ ] E.1 `logs/` populated
- [ ] F — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "parameter-optimization",
  "artifacts": [
    { "id": "A.1", "path": "filter_analysis.json", "type": "json" },
    { "id": "B.1", "path": "optimized_payloads.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "C.1", "path": "mined_params.txt", "type": "text" },
    { "id": "D.1", "path": "summary.md", "type": "text" },
    { "id": "E.1", "path": "logs", "type": "dir" }
  ]
}
```
