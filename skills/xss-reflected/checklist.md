# Reflected XSS — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Context
- [ ] Ingest injection points / sinks / CSP (feeder or js-analysis)
- [ ] Confirm params reflect; mine extra params
  - [ ] arjun/x8 run
  - [ ] marker reflection confirmed

## Map
- [ ] Reflection probe (unique marker per point)
- [ ] Context classification
  - [ ] html body
  - [ ] attribute (quoted / unquoted)
  - [ ] js string / template
  - [ ] uri / href
  - [ ] comment

## Exploit (scope-gated)
- [ ] Payload selection per context
- [ ] Filter / WAF probing
  - [ ] encoding escalation recorded
- [ ] Execution confirmed in real browser (not just reflection)
  - [ ] alert / DOM mutation / callback captured
  - [ ] CSP checked (blocks execution? → downgrade)
- [ ] Request/response captured for working payload
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (req_resp + screenshot + dom)
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical, review.md) passes
- [ ] /VERIFY (semantic, verify.md) — every finding accepted or rejected with reason
