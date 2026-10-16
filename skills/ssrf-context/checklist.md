# SSRF Context — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Enumerate
- [ ] Candidate URL-fetching sinks found
  - [ ] query/body params (url, uri, src, dest, feed, callback, webhook, import)
  - [ ] features (image/PDF proxy, import-from-url, link preview, SSO metadata, avatar)

## Probe
- [ ] Benign OOB fetch confirmed per sink (server actually fetches)
- [ ] Behavior characterized
  - [ ] in-band reflection of response?
  - [ ] follows redirects?
  - [ ] protocols accepted (http/https/gopher/file/dict)?
  - [ ] allowlist / parser behavior

## Route + emit
- [ ] variant_hint per sink (inband / blind / cloud)
- [ ] in-scope internal targets + metadata endpoints listed
- [ ] ssrf_context.json validates against _contract/ssrf_context.schema.json
- [ ] summary.md
- [ ] /REVIEW SKILL passes
