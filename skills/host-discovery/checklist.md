# Host Discovery — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Enumerate
- [ ] Scope + OSINT subs ingested
- [ ] Active subdomain enum (in-scope only)
- [ ] Resolved + deduped

## Probe (scope-gated, rate-limited)
- [ ] Live hosts probed (status / title / tech)
- [ ] Port/service scan (scoped, top-ports-first, rate-limited)
- [ ] Out-of-scope subs reported (NOT probed)

## Emit
- [ ] subdomains.txt
- [ ] hosts.json
- [ ] host_discovery.json
- [ ] summary.md
- [ ] /REVIEW SKILL passes
