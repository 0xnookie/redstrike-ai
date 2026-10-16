# Stored XSS — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Candidates
- [ ] Ingest stored candidates from xss_context.json (persists == true)
- [ ] Include accepted-but-unseen inputs (blind-stored handoff noted)

## Map store → render
- [ ] Enumerate render surfaces + viewer privilege
  - [ ] same-user
  - [ ] other-user
  - [ ] admin
  - [ ] anonymous
- [ ] Submit benign tracer per candidate
- [ ] Confirm which surface/viewer each tracer renders on
- [ ] Classify context at the RENDER surface
  - [ ] output encoder / sanitizer canary recorded

## Exploit (scope-gated, benign payloads)
- [ ] Payload selection per render context
- [ ] Store-side + output-side sanitizer probing
  - [ ] encoding/bypass escalation recorded
- [ ] Execution confirmed on render surface as a DIFFERENT user/session
  - [ ] alert / DOM mutation / OOB callback captured
  - [ ] CSP checked
- [ ] Durability confirmed (fresh session / after logout)
- [ ] Blast radius assessed (who views the surface)
- [ ] PoC captured at BOTH ends (store_req + render evidence)
- [ ] CVSS rated (cross-user elevation justified by evidence)

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (store_req + render_*)
- [ ] cleanup.md (stored artifacts + removal steps)
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical, review.md) passes
- [ ] /VERIFY (semantic, verify.md) — every finding accepted or rejected with reason
