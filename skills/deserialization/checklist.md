# Insecure Deserialization — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Deserialize sinks ingested from injection_context.json
- [ ] Format identified (java / php / python / .net / node)
- [ ] Approval obtained (RoE — RCE class)

## Confirm (benign)
- [ ] BENIGN gadget sent (URLDNS / DNS-only — no code exec)
- [ ] OOB callback correlated (proves deserialization of attacker data)
- [ ] Gadget-chain feasibility assessed (available libs)
- [ ] Benign RCE proof via OOB — if approved
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (gadget + callback evidence)
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes  [empty callbacks.jsonl is a valid liveness PASS]
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
