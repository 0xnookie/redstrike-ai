# Prototype Pollution — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Params + JSON/merge sinks identified (from js-analysis)
- [ ] Approval obtained (RoE)

## Inject (scope-gated, benign)
- [ ] Client-side pollution tried (URL __proto__[x], hash, JSON input)
- [ ] Server-side pollution tried (JSON body recursive merge)
- [ ] constructor.prototype bypass form tried (where __proto__ is filtered)
- [ ] Pollution CONFIRMED (fresh object carries injected prop)
- [ ] Gadget hunted (client XSS / server RCE / DoS)
- [ ] Impact confirmed benignly (where a gadget exists)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
