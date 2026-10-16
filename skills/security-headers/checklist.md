# Security Headers — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Collect
- [ ] Headers collected across key pages (authed + unauthed)
- [ ] Cookie flags collected (Secure / HttpOnly / SameSite)

## Evaluate
- [ ] Matrix evaluated
  - [ ] CSP
  - [ ] HSTS
  - [ ] X-Frame-Options / frame-ancestors
  - [ ] X-Content-Type-Options
  - [ ] Referrer-Policy
  - [ ] Permissions-Policy
  - [ ] COOP / COEP / CORP
- [ ] Contextual exploitability assessed per gap (real attack path?)

## Rate
- [ ] Honest severity (most Info/Low; elevate only with a concrete path)
- [ ] Cross-referenced dedicated agents (no double-reporting)

## Emit
- [ ] findings.json (schema-valid)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
