# SQLi Context — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Enumerate
- [ ] Candidate params enumerated (js-analysis)

## Probe (benign, SELECT-safe)
- [ ] Anomaly fuzz run per param ( ' " ) -- arithmetic boolean )
- [ ] Query context classified
  - [ ] string / numeric / identifier / order_by / like / json
- [ ] DBMS fingerprinted (error strings / behavior)
- [ ] Error visibility noted (→ in-band vs blind)
- [ ] WAF presence noted

## Route + emit
- [ ] variant_hint per point (inband / blind)
- [ ] sqli_context.json validates against _contract/sqli_context.schema.json
- [ ] summary.md
- [ ] /REVIEW SKILL passes
