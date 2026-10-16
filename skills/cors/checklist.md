# CORS — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Enumerate
- [ ] CORS-emitting endpoints found (ACAO present)
- [ ] Sensitive/credentialed endpoints identified

## Probe origin reflection
- [ ] arbitrary origin reflected?
- [ ] null origin accepted?
- [ ] pre/post-domain substring gaps (target.com.evil, eviltarget.com)?
- [ ] trusted-subdomain / regex gaps?
- [ ] ACAC:true present with reflection?

## Confirm (scope-gated)
- [ ] Credentialed cross-origin read of sensitive data confirmed
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
