# AuthZ Context — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/authz-context --out <out_dir>
# Recon feeder → liveness only, no verify.md.

- [ ] A — Objects
  - [ ] A.1 `objects.json` valid JSON
- [ ] B — Role matrix
  - [ ] B.1 `role_matrix.json` valid JSON, non-empty (≥2 identities mapped)
- [ ] C — Mass-assign
  - [ ] C.1 `mass_assign.json` valid JSON
- [ ] D — Context
  - [ ] D.1 `authz_context.json` valid JSON, non-empty
- [ ] E — Summary
  - [ ] E.1 `summary.md` non-zero
- [ ] F — Logs
  - [ ] F.1 `logs/` populated
- [ ] G — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "authz-context",
  "artifacts": [
    { "id": "A.1", "path": "objects.json", "type": "json", "allow_empty_array": true },
    { "id": "B.1", "path": "role_matrix.json", "type": "json" },
    { "id": "C.1", "path": "mass_assign.json", "type": "json", "allow_empty_array": true },
    { "id": "D.1", "path": "authz_context.json", "type": "json" },
    { "id": "E.1", "path": "summary.md", "type": "text" },
    { "id": "F.1", "path": "logs", "type": "dir" }
  ]
}
```
