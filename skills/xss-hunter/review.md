# XSS Hunter — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/xss-hunter --out <out_dir>
# Single-class mission orchestrator (inherits _contract/hunter-base.md) → liveness only, no verify.md
# (findings verified by the XSS variant agents' reviewers).
# An engagement with zero accepted findings is a valid PASS (empty submissions + a summary saying so).

- [ ] A — Program scope
  - [ ] A.1 `program_scope.json` valid JSON, non-empty
- [ ] B — Hunt plan
  - [ ] B.1 `hunt_plan.md` non-zero
- [ ] C — Submissions
  - [ ] C.1 `submissions/` directory (optional — empty if no accepted in-scope findings)
- [ ] D — Summary
  - [ ] D.1 `summary.md` non-zero
- [ ] E — Logs
  - [ ] E.1 `logs/` populated
- [ ] F — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "xss-hunter",
  "artifacts": [
    { "id": "A.1", "path": "program_scope.json", "type": "json" },
    { "id": "B.1", "path": "hunt_plan.md", "type": "text" },
    { "id": "C.1", "path": "submissions", "type": "dir", "required": false },
    { "id": "D.1", "path": "summary.md", "type": "text" },
    { "id": "E.1", "path": "logs", "type": "dir" }
  ]
}
```
