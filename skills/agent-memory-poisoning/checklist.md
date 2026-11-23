# Agent Memory & Context Poisoning (ASI06) — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Memory surface ingested from agent_context.json (endpoints / protocol / capability / injection_points / exposures+asi_refs)
- [ ] Approval obtained (RoE — writing the agent's memory store) + authorized TEST agent/memory store + in-scope confirmed

## Test (scope-gated, benign, test memory store only)
- [ ] Persistent-memory layer + reachable write path identified (store write / memory-tool arg / persisted tool output / summarised-to-memory)
- [ ] Session A: benign trigger→marker planted into the persistent store (labelled, benign marker)
- [ ] Session B (NEW, separate session): marker PERSISTED across the session boundary + trigger changes behaviour
- [ ] Clean control session run (unaffected) — rules out a one-session echo (that is prompt-injection)
- [ ] De-dup confirmed: not RAG/training-corpus poisoning (data-poisoning), not same-session injection (prompt-injection)
- [ ] No real memory/user data corrupted or deleted; benign marker only
- [ ] Planted memory REMOVED + removal verified (cleanup)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (session-A write + session-B cross-session read/behaviour + clean control + cleanup)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
