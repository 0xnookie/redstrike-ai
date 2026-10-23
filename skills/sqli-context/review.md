# SQLi Context — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/sqli-context --out <out_dir>
# Recon feeder → liveness only, no verify.md. Empty injectable set is a valid PASS, but probes must have run.

- [ ] A — Candidates
  - [ ] A.1 `candidates.json` valid JSON
- [ ] B — Probes
  - [ ] B.1 `probes.jsonl` ≥1 record, each line valid JSON
- [ ] C — Context
  - [ ] C.1 `sqli_context.json` valid JSON, non-empty
- [ ] D — Summary
  - [ ] D.1 `summary.md` non-zero
- [ ] E — Logs
  - [ ] E.1 `logs/` populated
- [ ] F — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "sqli-context",
  "artifacts": [
    { "id": "A.1", "path": "candidates.json", "type": "json", "allow_empty_array": true },
    { "id": "B.1", "path": "probes.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "C.1", "path": "sqli_context.json", "type": "json", "schema": "skills/_contract/sqli_context.schema.json" },
    { "id": "D.1", "path": "summary.md", "type": "text" },
    { "id": "E.1", "path": "logs", "type": "dir" }
  ]
}
```
