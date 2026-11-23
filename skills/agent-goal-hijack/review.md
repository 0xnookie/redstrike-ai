# Agent Goal Hijack (ASI01) — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/agent-goal-hijack --out <out_dir>
# Liveness only. goal_trace.jsonl may be empty (loop not drivable / planner held). Empty findings.json is a PASS.

- [ ] A — Hijack tests
  - [ ] A.1 `hijack_tests.jsonl` ≥1 record, each line valid JSON
- [ ] B — Goal trace
  - [ ] B.1 `goal_trace.jsonl` valid JSONL (MAY be empty)
- [ ] C — Findings
  - [ ] C.1 `findings.json` valid JSON (empty array → PASS)
- [ ] D — PoC (verify.md enforces when findings non-empty)
  - [ ] D.1 `poc/` (optional)
- [ ] E — Report
  - [ ] E.1 `report.md` non-zero
- [ ] F — Logs
  - [ ] F.1 `logs/` populated
- [ ] G — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "agent-goal-hijack",
  "artifacts": [
    { "id": "A.1", "path": "hijack_tests.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "B.1", "path": "goal_trace.jsonl", "type": "jsonl", "allow_empty": true },
    { "id": "C.1", "path": "findings.json", "type": "json", "allow_empty_array": true, "schema": "skills/_contract/finding.schema.json" },
    { "id": "D.1", "path": "poc", "type": "dir", "required": false },
    { "id": "E.1", "path": "report.md", "type": "text" },
    { "id": "F.1", "path": "logs", "type": "dir" }
  ]
}
```
