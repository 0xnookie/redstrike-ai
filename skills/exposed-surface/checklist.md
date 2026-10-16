# Exposed Surface — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Recon surface ingested (content-discovery + host-discovery + js-analysis)
- [ ] De-scoped to in-scope hosts → targets.txt
- [ ] Tech + WAF fingerprinted → fingerprint.json

## Fuzz (scope-gated, rate-limited, tool-first)
- [ ] Sensitive file/dir fuzz (sensitive_paths.txt + custom_wordlist) → fuzz_raw.jsonl
- [ ] Templated exposure scan (nuclei exposures/misconfig/panels/backups) → nuclei.jsonl
- [ ] Parameter fuzz/discovery → params_found.txt
- [ ] Soft-404 / wildcard baseline established + filtered

## Confirm
- [ ] Each candidate benignly signature-confirmed (body matches exposure_signatures.md)
- [ ] Evidence captured per candidate (request/response, redacted) → evidence/
- [ ] No mass exfiltration (single signature read; reconstructability noted, not dumped)
- [ ] De-duped vs secrets / security-headers / privesc
- [ ] Secrets handed to `secrets` for validation (not re-validated here)
- [ ] Classified (OWASP/CWE) + CVSS rated

## Emit
- [ ] findings.json (schema-valid; empty array if clean)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
