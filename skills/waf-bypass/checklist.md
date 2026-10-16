# WAF / Filter Bypass — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Profile
- [ ] Block confirmed (benign baseline 200 vs blocked payload 403/429/challenge)
- [ ] WAF/CDN fingerprinted (headers / cookies / challenge / routes)

## Bypass (benign canary, in scope)
- [ ] Encoding/case/comment transforms tried (per the blocked vuln-class)
- [ ] HTTP manipulation tried (headers / HPP / chunking / method case)
- [ ] TLS/JA3 + HTTP/2-3 angle considered
- [ ] Origin discovery considered (and any found IP scope-checked)
- [ ] Passing transform(s) recorded; benign canary confirmed through

## Emit
- [ ] waf_profile.json (WAF id + which transforms pass)
- [ ] bypass_notes.md (tuned ladder handed back to the calling agent)

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
# No verify.md — this capability emits no findings; the vuln agent it feeds owns verification.
