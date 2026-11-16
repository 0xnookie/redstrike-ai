# Strategist / hunt-planner — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Load state
- [ ] coverage_ledger.json read (routed/pending classes identified)
- [ ] surface_ledger.json read (surface breadth per class)
- [ ] the *_context.json feeders + notebook.json + cve_intel.json read (what's available); inputs_seen recorded
- [ ] scope.yaml read

## Rank
- [ ] every pending (and, on re-rank, not-yet-done) coverage category is represented in the queue
- [ ] each class scored from the ranking inputs (prior / surface / CVE / feeder / leads / severity / chaining)
- [ ] each class's depth budget read AT OR ABOVE its escalation-ladder floor (escalation.py) — never below
- [ ] per-class rationale written

## Invariant check
- [ ] NO class marked skipped/n/a (hunt_plan has no skipped state)
- [ ] NO ledger written (coverage_ledger.json / surface_ledger.json untouched; ledger_owner stays coverage.py)
- [ ] NO depth budget lowers the recall floor (every budget is floor-or-above)

## Emit
- [ ] hunt_plan.json (valid vs skills/_contract/hunt_plan.schema.json)
- [ ] summary.md
- [ ] logs/ populated
- [ ] /REVIEW SKILL passes
