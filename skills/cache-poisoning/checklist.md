# Web Cache Poisoning — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Map
- [ ] Cacheable responses identified (X-Cache/Age/Cache-Control)
- [ ] Cache key behavior understood (hit/miss via cache-buster)

## Discover
- [ ] Unkeyed inputs found
  - [ ] X-Forwarded-Host / Scheme / Port
  - [ ] X-Host / X-Original-URL / X-Rewrite-URL
  - [ ] unkeyed query params
- [ ] Reflection of unkeyed input into cacheable content

## Confirm (scope-gated, buster-scoped)
- [ ] Cross-user cache HIT of the poisoned response confirmed
- [ ] Impact assessed (cache XSS / redirect / DoS / deception of private page)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding
- [ ] cleanup.md (poison scoped to buster / purged)
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
