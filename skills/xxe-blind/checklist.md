# Blind XXE — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Setup
- [ ] Blind sinks ingested from xxe_context.json
- [ ] OOB + external DTD hosted (token scheme); oob.collaborator confirmed
- [ ] Approval obtained (RoE — file exfil)

## Confirm (benign)
- [ ] Parameter-entity payload sent
- [ ] External-DTD resolution confirmed via callback
- [ ] Benign file exfil over OOB (/etc/hostname) — if approved
- [ ] CVSS rated

## Emit
- [ ] findings.json (callback-backed; schema-valid)
- [ ] poc/ per finding
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes  [empty callbacks.jsonl is a valid liveness PASS]
- [ ] /VERIFY (semantic) — every finding backed by an attributable callback
