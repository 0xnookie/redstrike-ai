# Forbidden / 403 Bypass — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Restricted endpoints (baseline 401/403) collected from content-discovery + crawl
- [ ] Approval obtained (RoE); scope confirmed

## Baseline
- [ ] Each endpoint baselined — genuinely denies (status + body length/hash recorded)
- [ ] Success oracle captured (known-200 sibling / expected marker) to distinguish granted vs. soft-404

## Test (scope-gated, read-only, raw path — no client normalization)
- [ ] Path/URL manipulations (trailing, dot-segment, `..;/`, encoding, case, matrix params)
- [ ] HTTP method swaps + method-override headers
- [ ] Trust/forwarding headers (XFF, X-Original-URL, X-Rewrite-URL, X-Forwarded-*, Referer)
- [ ] Protocol/version manipulations
- [ ] Combined-axis manipulations on survivors
- [ ] Access confirmed — REAL restricted content/behaviour reached (body-signature match, not status-only)
- [ ] CVSS rated

## Emit
- [ ] restricted_endpoints.jsonl
- [ ] bypass_tests.jsonl
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (baseline-denied vs. bypass-granted)
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
