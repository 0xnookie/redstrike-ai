# Open Redirect — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Collect
- [ ] Redirect params collected (js-analysis groups + observed)

## Probe
- [ ] Mechanism per param (Location 3xx / JS location / meta refresh)
- [ ] Payloads tested
  - [ ] scheme-relative // and absolute
  - [ ] allowlist bypass (pre/post-domain, @, \, #, unicode, CRLF)
  - [ ] javascript: (client-side sinks)

## Confirm
- [ ] External redirect to attacker host confirmed
- [ ] Impact chain assessed (OAuth/SSO token leak / SSRF / XSS)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding
- [ ] report.md
- [ ] curl_commands.sh

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
