# Blind SSRF — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Setup
- [ ] Blind sinks ingested from ssrf_context.json
- [ ] OOB listener up (token scheme); oob.collaborator confirmed

## Probe
- [ ] Token-tagged fetch URLs sent per sink
- [ ] Callbacks correlated (token → sink, egress IP)
- [ ] Internal reachability probed by timing (optional, in-scope)

## Rate + emit
- [ ] CVSS rated (conservative — blind)
- [ ] findings.json (callback-backed; schema-valid)
- [ ] poc/ per finding (probe + callback evidence)
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes  [empty callbacks.jsonl is a valid liveness PASS]
- [ ] /VERIFY (semantic) — every finding backed by an attributable callback
