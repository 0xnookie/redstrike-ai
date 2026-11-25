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
- [ ] Cache-key-injection probe (delimiter-less key → keyed-input collision)
  - [ ] Split-invariance probe run (same bytes split two ways across a seam)
  - [ ] Boundary-confusion primitive identified (uri↔header / scheme↔host / empty-fragment)

## Confirm (scope-gated, buster-scoped)
- [ ] Cross-request cache HIT confirmed (unkeyed-input reflection OR key-collision pair)
- [ ] Impact assessed (cache XSS / redirect / DoS / deception / CKI ACL-bypass read)
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
