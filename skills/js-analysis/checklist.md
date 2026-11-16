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
  - [ ] DOM sinks
  - [ ] postMessage handlers (origin-check strength, message types, routed sinks)

## Analyze
- [ ] Params & route analysis
  - [ ] all carriers (query · body · form · header · cookie · storage · data-*)
  - [ ] SPA router tables (framework routers; guarded vs unguarded)
  - [ ] admin
  - [ ] feature flags
  - [ ] interesting comments
- [ ] API analysis
  - [ ] old versions
  - [ ] all calls grouped by functionality
  - [ ] GraphQL operations + root fields
- [ ] Library analysis
  - [ ] outdated
  - [ ] security (CVEs)
- [ ] Framework & tech analysis
- [ ] Feature map
- [ ] Secrets (known-regex vs high-entropy strings)
  - [ ] offline enrichment (provider/account/key-type · JWT decode + expiry · demo/placeholder tagging) — never validated against the issuer
- [ ] AST produced for every external file (ast/external/{name}.ast.json)
- [ ] symbols.json built (globals, exports, definition sites)
- [ ] Per-file note for every inline block (analysis/inline/)
- [ ] Per-file note for every external file (analysis/external/)
- [ ] site-summary.md written
- [ ] Findings emitted as JSONL (endpoints, params, apis, secrets, gadgets, libraries)

## Emit
- [ ] report.md
- [ ] curl_commands.sh
- [ ] exports/ (OPTIONAL) — openapi.json · postman_collection.json · findings.sarif
