# DOM XSS — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Candidates
- [ ] Ingest DOM candidates from xss_context.json (dom.source_sink_flows + sources/sinks)
- [ ] Include fragment / postMessage / window.name sources

## Gadgets (gather)
- [ ] Scan beautified JS for source→sink chains
- [ ] postMessage handlers enumerated
  - [ ] origin check present? (missing = exploitable)
- [ ] Prototype-pollution sources + gadget sinks
- [ ] Library/framework client-template sinks

## Taint
- [ ] Taint-trace each candidate flow (source → sink)
  - [ ] path confirmed via DOM/event breakpoints

## Exploit (scope-gated, client-side)
- [ ] Source delivery crafted (hash / search / window.name / postMessage / storage)
- [ ] Sink filter / Trusted Types / CSP probing
  - [ ] encoding/bypass escalation recorded
- [ ] Execution confirmed in real browser at the sink
  - [ ] devtools taint trace captured
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (crafted url / pm script + screenshot + dom + trace)
- [ ] poc_urls.txt (one-click PoC URLs)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical, review.md) passes
- [ ] /VERIFY (semantic, verify.md) — every finding accepted or rejected with reason
