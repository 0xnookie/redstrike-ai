# Persistence — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Foothold
- [ ] In-scope landed host + current privilege confirmed
- [ ] Approval obtained (RoE — post-exploitation, HIGH-RISK)

## Enumerate (opportunities for the current privilege)
- [ ] Persistence opportunities enumerated → persist_enum.json
- [ ] Each candidate recorded with the control/monitoring that should catch it

## Test (benign, reversible — exactly ONE)
- [ ] ONE benign-marker mechanism installed (writes a harmless timestamped marker on trigger; nothing else)
- [ ] Trigger exercised (logoff/reboot/schedule) + marker confirmed → poc/<id>/
- [ ] Detectability noted (did logging/EDR alert?) → persist_tests.jsonl
- [ ] Mechanism REMOVED completely + removal verified → cleanup.md
- [ ] No backdoor/shell/C2, no credential change, no defense disabled
- [ ] CVSS rated (control + monitoring gap)

## Emit
- [ ] findings.json (schema-valid; empty array if no gap)
- [ ] poc/ per finding (marker proof + removal proof)
- [ ] cleanup.md
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
