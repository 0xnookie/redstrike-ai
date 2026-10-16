# OSINT — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/osint --out <out_dir>
# Recon feeder → liveness only, no verify.md.

- [ ] A — OSINT
  - [ ] A.1 `osint.json` valid JSON, non-empty
- [ ] B — Terms
  - [ ] B.1 `terms.txt` non-zero
- [ ] C — Summary
  - [ ] C.1 `summary.md` non-zero
- [ ] D — Logs
  - [ ] D.1 `logs/` populated
- [ ] E — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "osint",
  "artifacts": [
    { "id": "A.1", "path": "osint.json", "type": "json" },
    { "id": "B.1", "path": "terms.txt", "type": "text" },
    { "id": "C.1", "path": "summary.md", "type": "text" },
    { "id": "D.1", "path": "logs", "type": "dir" }
  ]
}
```
