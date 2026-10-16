# XSS Context — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Attack surface ingested from js-analysis
  - [ ] endpoints (live + unauthed)
  - [ ] params
  - [ ] forms / JSON bodies
  - [ ] gadgets (sinks) + beautified JS

## Map surface
- [ ] Injection surface expanded (all sources)
  - [ ] query
  - [ ] body (form + JSON keys)
  - [ ] path
  - [ ] header
  - [ ] cookie
  - [ ] fragment
- [ ] Benign marker probe run per point
- [ ] Persistence check (stored candidates flagged)
- [ ] Reflection context classified
  - [ ] breakout-char encoding canary recorded

## Environment
- [ ] CSP + security headers captured
  - [ ] blocks inline?
  - [ ] blocks eval?
  - [ ] trusted types?
  - [ ] candidate bypass sources
- [ ] DOM source→sink flows mapped (dom candidates)

## Emit
- [ ] xss_context.json (validates against _contract/xss_context.schema.json)
- [ ] summary.md with per-point variant routing (reflected/stored/dom/blind)
- [ ] /REVIEW SKILL passes
