# Proxy Context — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/proxy-context --out <out_dir>
# Recon feeder → export/liveness only, no verify.md (emits no findings).

- [ ] A — Export
  - [ ] A.1 `http_history.json` valid JSON (an empty `exchanges[]` is valid when no proxy was connected — a SKIP)
- [ ] B — Summary
  - [ ] B.1 `summary.md` non-zero
- [ ] C — Logs
  - [ ] C.1 `logs/` populated
- [ ] D — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "proxy-context",
  "artifacts": [
    { "id": "A.1", "path": "http_history.json", "type": "json" },
    { "id": "B.1", "path": "summary.md", "type": "text" },
    { "id": "C.1", "path": "logs", "type": "dir" }
  ]
}
```
