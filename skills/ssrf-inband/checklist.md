# In-Band SSRF — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] In-band sinks + internal targets ingested from ssrf_context.json
- [ ] Approval obtained for reaching internal resources (RoE)

## Confirm (scope-gated)
- [ ] Sink pointed at an in-scope internal/unauthorized target
- [ ] In-band evidence of reach (reflected body / status / length diff)
- [ ] Bypass used where needed (allowlist / redirect / protocol)
- [ ] Impact assessed (internal read / port scan) — read-only
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (request + reflected internal response)
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
