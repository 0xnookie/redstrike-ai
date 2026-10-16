# Host Header Injection — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Identify
- [ ] Host-reflecting behaviors found
  - [ ] password-reset / email links
  - [ ] absolute URLs in responses
  - [ ] redirects
  - [ ] cache key (→ pairs with cache-poisoning)

## Test
- [ ] Header-override matrix
  - [ ] Host
  - [ ] X-Forwarded-Host
  - [ ] X-Host / X-Forwarded-Server
  - [ ] duplicate Host / absolute-URI request line

## Confirm (scope-gated, test account)
- [ ] Security-relevant sink confirmed (reset link host = attacker / cache / routing)
- [ ] CVSS rated (reset poisoning = high)

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
