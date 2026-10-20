# WordPress Agent — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Fingerprint
- [ ] WordPress confirmed + core version pinned from ≥2 independent signals (generator / readme.html / core asset `?ver=` / REST / login) — a single-signal guess is `tentative`, not a finding
- [ ] Upstream inputs consumed (js-analysis libraries.jsonl + site-summary; host-discovery CMS+version)
- [ ] framework.json written (framework, core version, signals[], confidence)

## Surface
- [ ] Plugins enumerated (slug + version) — the dominant WP vector
- [ ] Themes enumerated (slug + version)
- [ ] Users enumerated (REST `/wp-json/wp/v2/users` · `?author=N` redirect · login oracle)
- [ ] xmlrpc.php posture (enabled? pingback? system.multicall?) — FEASIBILITY only, no DoS/brute
- [ ] REST + config/backup/`debug.log` exposure checked (de-duped vs exposed-surface/secrets)
- [ ] Directory listing checked
- [ ] surface.json written

## Map
- [ ] Core version → version-APPLICABLE CVEs (exact range; mismatches dropped)
- [ ] Each plugin/theme version → version-APPLICABLE CVEs (slug AND version matched)
- [ ] Reachability assessed (plugin/theme ACTIVE vs merely installed; feature exposed)
- [ ] Generic non-WP library CVEs left to cve-intelligence (de-dupe)
- [ ] Exploit availability noted (exploit-db / metasploit / PoC ref)
- [ ] cve_map.json written

## Confirm
- [ ] Benign confirmation per candidate (version banner / benign nuclei check / differential) — NO exploitation
- [ ] Counterevidence applied (`_contract/counterevidence.md`): opposing case argued, each candidate closed confirmed/ruled-out/open-proof-gap

## Emit
- [ ] findings.json (reachable version-matched CVE exposure + WP misconfigs; schema-valid; CVSS tempered by reachability; potential_severity when version-only)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
