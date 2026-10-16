# JWT Attack — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] JWT decoded (alg, claims) from auth_context.json / auth.env
- [ ] Approval obtained (RoE); test account token

## Test
- [ ] alg:none (strip signature)
- [ ] weak HMAC secret crack (offline) → re-sign
- [ ] key confusion RS256→HS256
- [ ] kid / jku / x5u injection
- [ ] claim tampering (role / sub / admin / exp)
- [ ] forged token ACCEPTED confirmed (authed action/data)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (forged token + accepted response)
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
