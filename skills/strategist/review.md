# Strategist / hunt-planner — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/strategist --out <out_dir>
# Capability / planning skill → liveness only, no verify.md (emits no findings). It writes NO ledger
# and never marks a class skipped — the schema check below enforces the ranking-only shape.

- [ ] A — Hunt plan
  - [ ] A.1 `hunt_plan.json` valid JSON and conforms to `skills/_contract/hunt_plan.schema.json`
        (so `ledger_owner` == "coverage.py", every queue entry carries a depth_budget + rationale,
        and no entry uses a `skipped` queue-state — the schema has none)
- [ ] B — Summary
  - [ ] B.1 `summary.md` non-zero
- [ ] C — Logs
  - [ ] C.1 `logs/` populated
- [ ] D — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "strategist",
  "artifacts": [
    { "id": "A.1", "path": "hunt_plan.json", "type": "json", "schema": "skills/_contract/hunt_plan.schema.json" },
    { "id": "B.1", "path": "summary.md", "type": "text" },
    { "id": "C.1", "path": "logs", "type": "dir" }
  ]
}
```
