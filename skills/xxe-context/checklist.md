# XXE Context — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Enumerate
- [ ] XML-accepting endpoints/uploads found
  - [ ] XML/SOAP content-types
  - [ ] SVG / DOCX / XLSX uploads
  - [ ] SAML / RSS / sitemap

## Probe (benign)
- [ ] Benign INTERNAL entity sent per sink
- [ ] Entity resolution confirmed (value reflected)
- [ ] Error reflection noted (→ in-band vs blind)

## Route + emit
- [ ] variant_hint per sink (inband / blind)
- [ ] xxe_context.json validates against _contract/xxe_context.schema.json
- [ ] summary.md
- [ ] /REVIEW SKILL passes
