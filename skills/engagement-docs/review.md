# Engagement Docs — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/engagement-docs --out <out_dir>
# Documentation skill → liveness only, no verify.md. Pre-engagement: report is a scope/plan stub (still non-zero).

- [ ] A — RoE
  - [ ] A.1 `RoE.md` non-zero (scope + authorization + restrictions + contacts + sign-off)
- [ ] B — Report
  - [ ] B.1 `report.md` non-zero (exec summary + findings, or a pre-engagement scope/plan stub)
- [ ] C — Attestation
  - [ ] C.1 `attestation.md` non-zero
- [ ] D — Retest
  - [ ] D.1 `retest.md` non-zero
- [ ] E — Summary
  - [ ] E.1 `summary.md` non-zero
- [ ] F — Logs
  - [ ] F.1 `logs/` populated
- [ ] G — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "engagement-docs",
  "artifacts": [
    { "id": "A.1", "path": "RoE.md", "type": "text" },
    { "id": "B.1", "path": "report.md", "type": "text" },
    { "id": "C.1", "path": "attestation.md", "type": "text" },
    { "id": "D.1", "path": "retest.md", "type": "text" },
    { "id": "E.1", "path": "summary.md", "type": "text" },
    { "id": "F.1", "path": "logs", "type": "dir" }
  ]
}
```
