# SSRF Context — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Enumerate
- [ ] Candidate URL-fetching sinks found
  - [ ] query/body params (url, uri, src, dest, feed, callback, webhook, import)
  - [ ] features (image/PDF proxy, import-from-url, link preview, SSO metadata, avatar)

## Probe
- [ ] Benign OOB fetch confirmed per sink (EXTERNAL benign OOB URL only — NEVER probe 169.254.0.0/16 / loopback / RFC1918 here; that is ssrf-cloud/inband/blind under approval)
- [ ] Behavior characterized
  - [ ] in-band reflection of response?
  - [ ] follows redirects?
  - [ ] protocols accepted (http/https/gopher/file/dict)?
  - [ ] allowlist / parser behavior

## Route + emit
- [ ] variant_hint per sink (inband / blind / cloud)
- [ ] in-scope internal targets + metadata endpoints LISTED for the variant (routing only — the feeder does not probe them)
- [ ] ssrf_context.json validates against _contract/ssrf_context.schema.json
- [ ] summary.md
- [ ] /REVIEW SKILL passes
