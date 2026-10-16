# Content Discovery — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Crawl
- [ ] Live hosts + osint terms ingested
- [ ] Crawled each live host (spider, JS-aware)
- [ ] Historical URLs merged (gau/waymore)

## Wordlist
- [ ] Custom wordlist built (osint terms + crawl paths + js strings + base) → custom_wordlist.txt

## Discover (scope-gated, rate-limited)
- [ ] Directory/file brute-force (custom + standard list)
- [ ] Parameter discovery (crawl + active mining)

## Emit
- [ ] crawl.txt · endpoints.txt · params.txt
- [ ] content.json
- [ ] summary.md
- [ ] /REVIEW SKILL passes
