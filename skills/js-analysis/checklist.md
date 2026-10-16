# JS Analysis — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done. (semantics are load-bearing)

## Collect
- [ ] Find & download all JS
  - [ ] inline + files (spider)
  - [ ] lazy-loaded
  - [ ] historical
  - [ ] sourcemaps
  - [ ] anti-automation escalation used where blocked
    - [ ] webfetch
    - [ ] curl
    - [ ] interceptor
    - [ ] chrome-devtools-mcp
    - [ ] puppeteer
- [ ] Store raw (deduped, hashed)
- [ ] Un-obfuscate (minified / obfuscated)
- [ ] Map gadgets & dangerous functions

## Analyze
- [ ] Params & route analysis
  - [ ] admin
  - [ ] feature flags
  - [ ] interesting comments
- [ ] API analysis
  - [ ] old versions
  - [ ] all calls grouped by functionality
- [ ] Library analysis
  - [ ] outdated
  - [ ] security (CVEs)
- [ ] Framework & tech analysis
- [ ] Feature map
- [ ] Secrets (known-regex vs high-entropy strings)

## Emit
- [ ] report.md
- [ ] curl_commands.sh
