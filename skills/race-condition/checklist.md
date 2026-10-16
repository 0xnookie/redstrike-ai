# Race Condition — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Single-use/limited actions + TOCTOU points identified (from js-analysis + business-logic)
- [ ] Approval obtained (RoE — state-changing) + test account ready

## Test (scope-gated, benign, bounded concurrency)
- [ ] Serial baseline confirms the action is normally limited
- [ ] Concurrent burst fired (single-packet HTTP/2 or last-byte HTTP/1), bounded
- [ ] Break detected vs baseline (redeemed >1x / double-spend / quota bypass / duplicate unique)
- [ ] Reproduced (not a one-off); serial attempts do NOT reproduce it
- [ ] State reverted (refund/void/delete) + recorded
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (concurrency script + before/after state)
- [ ] report.md
- [ ] curl_commands.sh (or turbo-intruder script)

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
