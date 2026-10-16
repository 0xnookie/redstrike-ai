# JS Analysis

> RECON skill (no vuln-variant split). Upstream FEEDER for content-discovery and
> the per-vuln (xss-*, etc.) skills. Read-only; honors `_contract/roe-gate.md` on fetches.
> Gold standard — pattern-match new skills against this one.

## Interview
- **STEPS:** enumerate → fetch (with escalation) → store/normalize → deobfuscate → endpoints → params/routes → APIs → secrets → gadgets/sinks → libraries + framework/tech → feature map → emit report + curl → review.
- **TOOLS:** see §Tools (modern-first, with the anti-automation ladder).
- **GOAL:** Produce a complete intelligence picture of a target's client-side JS — every endpoint, param, API, secret, dangerous sink, and tech choice — as an MD report plus ready-to-run curl commands. Done = all checklist boxes checked AND review passes.
- **OUTPUT:** `js_sources.txt`, `js/raw/`, `js/beautified/`, `endpoints_{live,historical,unauthed}.txt`, `params.txt`, `routes.md`, `apis.json`, `secrets.json`, `gadgets.md`, `libraries.json`, `tech.md`, `feature_map.md`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = scope roots + optional auth (cookies/headers for authed-vs-unauthed diff). `refs/` corpus = secret regexes, dangerous-sink list, retire.js vuln-lib signatures, param-mining wordlist. Chains FROM host discovery; chains TO content-discovery (feeds `custom_list.txt`) and the DOM-XSS agent (consumes `gadgets.md` + endpoints).
- **DECOMPOSITION:** n/a (recon, not a vuln class).

## Goal
Build a full intelligence picture of a target's client-side JavaScript and emit it
as `report.md` + `curl_commands.sh`.
DONE = every box in `checklist.md` is `- [x]` AND `review.md` passes (all artifacts
exist, non-zero, expected format).

## What do we want
- Endpoints
  - live
  - historical
  - unauthed (reachable without a session)
- Params
  - all
  - statistically-likely-vulnerable
- APIs (grouped by functionality, incl. old/deprecated versions)
- Secrets (keys, tokens, creds)
- Vuln functions (dangerous sinks / gadgets)
- Tech choices (framework, build, libraries + versions)

## Steps  (action · tool · output)
1. Enumerate JS sources (inline + files, lazy, historical, sourcemaps) · `katana -jc` / `gau` / `waymore` / `subjs` · `js_sources.txt`
2. Fetch all JS via escalation ladder (see §Tools) · → · `js/raw/` + `logs/fetch.log`
3. Pull & unpack sourcemaps where present · `sourcemapper` / `unwebpack-sourcemap` · `js/raw/_sourcemaps/`
4. Store + normalize (dedupe by hash) · `sha256` + `cp` · `js/raw/index.csv`
5. Deobfuscate / beautify minified · `webcrack` → `js-beautify` · `js/beautified/`
6. Extract endpoints; split live/historical/unauthed · `jsluice urls` / `xnLinkFinder` · `endpoints_live.txt`, `endpoints_historical.txt`, `endpoints_unauthed.txt`
7. Extract params + routes (admin, feature flags, interesting comments) · `jsluice` / `xnLinkFinder` + `grep` · `params.txt`, `routes.md`
8. Extract APIs, group by functionality, flag old versions · `grep` + `jq` · `apis.json`
9. Extract secrets (known-regex vs high-entropy) · `trufflehog` + `gitleaks` + `jsluice secrets` · `secrets.json`
10. Map gadgets & dangerous functions (DOM sinks) · `semgrep` (`refs/dangerous_sinks.yaml`) + `grep` · `gadgets.md`
11. Library analysis (outdated + CVEs) · `retire.js` · `libraries.json`
12. Framework & tech analysis · `httpx -td` / `nuclei -t http/technologies` · `tech.md`
13. Feature map (what the app does, derived from endpoints+routes+APIs) · synth · `feature_map.md`
14. Emit MD report + curl commands for every live/unauthed endpoint · synth + `printf` · `report.md`, `curl_commands.sh`
15. /REVIEW SKILL · `review.md`

## Tools
- **Enumerate:** `katana` (`-jc -jsl`), `gau`, `waymore`, `subjs`/`getJS`, `hakrawler` (alt)
- **Fetch ladder** (ANTI-AUTOMATION — escalate only when the prior rung is blocked; see `_contract/anti-automation-ladder.md`):
  `webfetch` → `curl` (UA+headers+auth) → interceptor (mitmproxy/Caido, manual browse) → `chrome-devtools-mcp` (headless, capture Network, lazy-load) → `puppeteer`/`playwright` (scroll+trigger)
- **Sourcemaps:** `sourcemapper`, `unwebpack-sourcemap`
- **Deobfuscate:** `webcrack` (webpack unbundle), `js-beautify`, `prettier`
- **Endpoints/params:** `jsluice`, `xnLinkFinder`, `LinkFinder`; `arjun`/`x8` to actively confirm params
- **Secrets:** `trufflehog` (filesystem), `gitleaks` (dir), `jsluice secrets`, `secretfinder`/`mantra`
- **Libs/tech:** `retire.js`, `nuclei` (`http/exposures`, `http/technologies`, `javascript/`), `httpx -td`
- **Glue:** `jq`, `semgrep`, `ripgrep`

## Inputs
- `scope.txt` (roots/domains in scope)
- optional `auth.env` (`COOKIE=`, `HEADERS=`) → enables authed-vs-unauthed endpoint diff
- `refs/` (RAG): `secret_regexes.yaml`, `dangerous_sinks.yaml`, `retire_signatures.json`, `param_wordlist.txt`

## Outputs
`js_sources.txt` · `js/raw/` · `js/beautified/` · `endpoints_{live,historical,unauthed}.txt` · `params.txt` · `routes.md` · `apis.json` · `secrets.json` · `gadgets.md` · `libraries.json` · `tech.md` · `feature_map.md` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** passive enumerate + historical + fetch + store + deobfuscate.
- **Phase 2 (target-specific):** endpoints/params/APIs/secrets/gadgets/tech + report.
