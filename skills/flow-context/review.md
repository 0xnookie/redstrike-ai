# Flow Context — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/flow-context --out <out_dir>
# Recon feeder → liveness only, no verify.md.

- [ ] A — States
  - [ ] A.1 `states.json` valid JSON, non-empty (≥2 identities mapped across reachable_by)
- [ ] B — Transitions
  - [ ] B.1 `transitions.json` valid JSON
- [ ] C — Invariants
  - [ ] C.1 `invariants.json` valid JSON
- [ ] D — Context
  - [ ] D.1 `flow_context.json` valid JSON, non-empty
- [ ] E — Summary
  - [ ] E.1 `summary.md` non-zero
- [ ] F — Logs
  - [ ] F.1 `logs/` populated
- [ ] G — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "flow-context",
  "artifacts": [
    { "id": "A.1", "path": "states.json", "type": "json" },
    { "id": "B.1", "path": "transitions.json", "type": "json", "allow_empty_array": true },
    { "id": "C.1", "path": "invariants.json", "type": "json", "allow_empty_array": true },
    { "id": "D.1", "path": "flow_context.json", "type": "json", "schema": "skills/_contract/flow_context.schema.json" },
    { "id": "E.1", "path": "summary.md", "type": "text" },
    { "id": "F.1", "path": "logs", "type": "dir" }
  ]
}
```
