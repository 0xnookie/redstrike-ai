# Host Discovery — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Enumerate
- [ ] Scope + OSINT subs ingested
- [ ] Active subdomain enum (in-scope only)
- [ ] Resolved + deduped (CNAME/A/NS)
- [ ] Dangling-DNS triage run (`scripts/dangling_dns.py`) → `asset:dangling-dns` emitted if a takeover candidate surfaced

## Probe (scope-gated, rate-limited)
- [ ] Live hosts probed (status / title / tech)
- [ ] Port/service scan (scoped, top-ports-first, rate-limited)
- [ ] Out-of-scope subs reported (NOT probed)

## Emit
- [ ] subdomains.txt
- [ ] hosts.json
- [ ] host_discovery.json
- [ ] dangling_dns.json (+ `asset:dangling-dns` signal when a candidate surfaced)
- [ ] summary.md
- [ ] /REVIEW SKILL passes
