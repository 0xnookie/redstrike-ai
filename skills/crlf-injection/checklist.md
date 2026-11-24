# CRLF Injection (HTTP response splitting / header injection) — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Params/endpoints that reach a RESPONSE HEADER sink ingested from content-discovery + injection-context + js-analysis
- [ ] Header sink classified per param (Location / Set-Cookie / reflected custom header)
- [ ] Baseline response headers captured per candidate (no CR/LF)
- [ ] Approval obtained (RoE — active CRLF probe; a split can touch a shared cache)

## Inject (scope-gated, benign, self-scoped with a unique cache-buster)
- [ ] Header-add probe (`%0d%0aX-CRLF-Test:<marker>`; LF-only → CRLF → double-encoded → null-byte-prefixed)
- [ ] `Set-Cookie` injection probe
- [ ] Response-split probe (self-scoped cache-buster; no full malicious second response served to others)
- [ ] The injected header/marker appears in the RESPONSE HEADER block, OR a genuine second `HTTP/1.x` start-line is parsed — not a body-only reflection, not a bare 200/302
- [ ] Causality differential: removing the CR/LF restores the normal response (marker/second response disappears)
- [ ] Any carried secret redacted to a fingerprint
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (payload + the raw response-header block / parsed split + the baseline differential)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes  [empty callbacks.jsonl is a valid liveness PASS]
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
