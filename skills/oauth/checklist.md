# OAuth / OIDC — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] OAuth config ingested from auth_context.json
- [ ] Approval obtained (RoE); test accounts prepared

## Test (scope-gated, test accounts)
- [ ] redirect_uri manipulation (suffix / subdomain / path / open-redirect in allowlist)
- [ ] state / CSRF (missing / replayable)
- [ ] code reuse
- [ ] PKCE downgrade
- [ ] implicit-flow token-in-fragment leak
- [ ] id_token validation (aud / iss / sig)
- [ ] Leak/takeover confirmed (code/token at OOB / account linked)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
