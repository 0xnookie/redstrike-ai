# LLM Context — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/llm-context --out <out_dir>
# Recon feeder → liveness only, no verify.md.

- [ ] A — API map
  - [ ] A.1 `api_map.json` valid JSON, non-empty
- [ ] B — Surface probes
  - [ ] B.1 `surface_probes.jsonl` ≥1 record, each line valid JSON
- [ ] C — Context
  - [ ] C.1 `llm_context.json` valid JSON, non-empty
- [ ] D — Summary
  - [ ] D.1 `summary.md` non-zero
- [ ] E — Logs
  - [ ] E.1 `logs/` populated
- [ ] F — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "llm-context",
  "artifacts": [
    { "id": "A.1", "path": "api_map.json", "type": "json" },
    { "id": "B.1", "path": "surface_probes.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "C.1", "path": "llm_context.json", "type": "json", "schema": "skills/_contract/llm_context.schema.json" },
    { "id": "D.1", "path": "summary.md", "type": "text" },
    { "id": "E.1", "path": "logs", "type": "dir" }
  ]
}
```
