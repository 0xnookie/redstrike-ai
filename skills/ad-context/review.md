# AD Context — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/ad-context --out <out_dir>
# Recon feeder → liveness only, no verify.md.

- [ ] A — Domain
  - [ ] A.1 `domain.json` valid JSON, non-empty
- [ ] B — BloodHound
  - [ ] B.1 `bloodhound/` directory populated
- [ ] C — Context
  - [ ] C.1 `ad_context.json` valid JSON, non-empty
- [ ] D — Summary
  - [ ] D.1 `summary.md` non-zero
- [ ] E — Logs
  - [ ] E.1 `logs/` populated
- [ ] F — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "ad-context",
  "artifacts": [
    { "id": "A.1", "path": "domain.json", "type": "json" },
    { "id": "B.1", "path": "bloodhound", "type": "dir", "min_children": 1 },
    { "id": "C.1", "path": "ad_context.json", "type": "json" },
    { "id": "D.1", "path": "summary.md", "type": "text" },
    { "id": "E.1", "path": "logs", "type": "dir" }
  ]
}
```
