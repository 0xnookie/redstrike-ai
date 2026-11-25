# WAF / Filter Bypass — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Profile (fingerprint FIRST)
- [ ] WAF/CDN fingerprinted FIRST (headers / cookies / challenge / routes) — you can't be WAF-safe or evade what you haven't identified
- [ ] WAF product/vendor + block-shell signature recorded in waf_profile.json AND the engagement
- [ ] Block confirmed (benign baseline 200 vs blocked payload 403/429/challenge) = a per-request CONTENT filter

## Egress hygiene (ALWAYS-ON — not a bypass, needs no evasion authorization)
- [ ] Egress-health baseline taken on a known-good public path (/robots.txt, /) — recon-expected status snapshotted
- [ ] Detection kept WAF-safe (benign/low-signal canaries, rate-capped; NO raw /etc/passwd · {{7*7}} · OR 1=1 · ../../ sprayed across hosts)
- [ ] Ban check: estate-wide recon-200→now-403/429 drift (or /robots.txt 403) read as YOUR egress banned → HALT (not a per-host policy deny); never evade/disguise to get back in
- [ ] If banned: recovery chosen (pause for the ban to lapse, OR rotate to a fresh AUTHORIZED egress) + resume gentle/WAF-safe; recorded in bypass_notes.md

## Bypass (benign canary, in scope — RoE-gated evasion-to-exploit)
- [ ] Evasion authorized by the RoE and recorded (roe-gate.md §2) BEFORE any ladder transform — this is content-filter evasion for a specific bug, NOT WAF-brute or client-fingerprint disguise
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
