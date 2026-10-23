# XXE Context — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/xxe-context --out <out_dir>
# Recon feeder → liveness only, no verify.md.

- [ ] A — XML sinks
  - [ ] A.1 `xml_sinks.json` valid JSON
- [ ] B — Entity probes
  - [ ] B.1 `entity_probes.jsonl` ≥1 record, each line valid JSON
- [ ] C — Context
  - [ ] C.1 `xxe_context.json` valid JSON, non-empty
- [ ] D — Summary
  - [ ] D.1 `summary.md` non-zero
- [ ] E — Logs
  - [ ] E.1 `logs/` populated
- [ ] F — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "xxe-context",
  "artifacts": [
    { "id": "A.1", "path": "xml_sinks.json", "type": "json", "allow_empty_array": true },
    { "id": "B.1", "path": "entity_probes.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "C.1", "path": "xxe_context.json", "type": "json", "schema": "skills/_contract/xxe_context.schema.json" },
    { "id": "D.1", "path": "summary.md", "type": "text" },
    { "id": "E.1", "path": "logs", "type": "dir" }
  ]
}
```
