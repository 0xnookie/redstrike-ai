# Social Engineering — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Explicit WRITTEN authorization naming the target population on file
- [ ] Authorized sender domains + target group + time window confirmed (RoE)
- [ ] No out-of-scope individuals / third parties / non-consenting people included

## Test (scope-gated, benign, aggregate)
- [ ] Pretext + campaign designed (sender, landing/harvest page, tracking)
- [ ] Delivery option chosen + approved (link / benign attachment / OAuth-consent) — NO real malware
- [ ] Targeting limited to the authorized population (scoped OSINT only)
- [ ] Approved time-boxed simulation run; click/submit/report events collected
- [ ] Harvest page never stored real passwords (hash+discard / accept-and-redirect)
- [ ] Vishing/smishing (if in scope) with a benign pretext against the authorized group
- [ ] Aggregate metrics computed + control gaps identified (no named-person blame)
- [ ] CVSS rated (process/control level)

## Emit
- [ ] findings.json (schema-valid, aggregate, sensitive data redacted)
- [ ] poc/ per finding (campaign config + aggregate evidence)
- [ ] report.md

## Gates
- [ ] Campaign + harvest page torn down
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
