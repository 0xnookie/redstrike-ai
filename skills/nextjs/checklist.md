# Next.js Agent — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Fingerprint
- [ ] Next.js confirmed + version pinned from ≥2 independent signals (`x-powered-by`, `__NEXT_DATA__` buildId, `_buildManifest.js`, `x-nextjs-*`, source-map version) — a single-signal guess is `tentative`, not a finding
- [ ] Upstream inputs consumed (js-analysis libraries.jsonl + site-summary; host-discovery tech+version)
- [ ] framework.json written (framework, version, buildId, signals[], confidence)

## Surface
- [ ] Middleware posture determined (does a route guard exist? which paths?)
- [ ] Image optimizer `/_next/image?url=` present + whether external/internal URLs are fetched (SSRF-class)
- [ ] Source maps `/_next/static/**/*.map` exposure checked (de-dupe → secrets)
- [ ] Server actions / `/api/*` routes mapped
- [ ] RSC / cache posture checked (`x-nextjs-cache`, prefetch/RSC headers)
- [ ] Data routes `/_next/data/<buildId>/*.json` checked for over-fetch (de-dupe → idor/bola)
- [ ] surface.json written

## Map
- [ ] Version → version-APPLICABLE Next CVEs (exact range; patched-in-version check; mismatches dropped)
- [ ] CVE-2025-29927 middleware bypass applicability assessed against the pinned version
- [ ] Reachability assessed (middleware actually guards a route? optimizer enabled? maps present?)
- [ ] Generic non-Next library CVEs left to cve-intelligence (de-dupe)
- [ ] Exploit availability noted (exploit-db / PoC ref)
- [ ] cve_map.json written

## Confirm
- [ ] Benign confirmation per candidate (version banner + behaviour/header differential) — NO exploitation, NO protected-data exfil
- [ ] Counterevidence applied (`_contract/counterevidence.md`): opposing case argued, each candidate closed confirmed/ruled-out/open-proof-gap

## Emit
- [ ] findings.json (reachable version-matched CVE exposure + Next misconfigs; schema-valid; CVSS tempered by reachability; potential_severity when version-only)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
