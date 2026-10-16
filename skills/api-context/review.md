# API Context — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/api-context --out <out_dir>
# Recon feeder → liveness only, no verify.md. graphql_schema.json may be empty for REST-only targets.

- [ ] A — Endpoints
  - [ ] A.1 `endpoints.json` valid JSON, non-empty
- [ ] B — GraphQL schema
  - [ ] B.1 `graphql_schema.json` valid JSON (may be empty object for REST-only)
- [ ] C — Context
  - [ ] C.1 `api_context.json` valid JSON, non-empty
- [ ] D — Summary
  - [ ] D.1 `summary.md` non-zero
- [ ] E — Logs
  - [ ] E.1 `logs/` populated
- [ ] F — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "api-context",
  "artifacts": [
    { "id": "A.1", "path": "endpoints.json", "type": "json" },
    { "id": "B.1", "path": "graphql_schema.json", "type": "json", "allow_empty_object": true, "allow_empty_array": true },
    { "id": "C.1", "path": "api_context.json", "type": "json" },
    { "id": "D.1", "path": "summary.md", "type": "text" },
    { "id": "E.1", "path": "logs", "type": "dir" }
  ]
}
```
