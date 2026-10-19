# JS Analysis

> RECON skill (no vuln-variant split). Upstream FEEDER for content-discovery and
> the per-vuln (xss-*, etc.) skills. Read-only; honors `_contract/roe-gate.md` on fetches.
> Gold standard — pattern-match new skills against this one.

## Interview
- **STEPS:** enumerate → fetch (with escalation) → store/normalize → deobfuscate → **parse AST → build symbol table** → endpoints → params/routes → APIs → secrets → gadgets/sinks → libraries + framework/tech → **per-file notes → site-summary** → emit report + curl → review.
- **TOOLS:** see §Tools (modern-first, with the anti-automation ladder).
- **GOAL:** Produce a complete intelligence picture of a target's client-side JS — every endpoint, param, API, secret, dangerous sink, and tech choice — as an MD report plus ready-to-run curl commands. Done = all checklist boxes checked AND review passes.
- **OUTPUT:** one `out/<site>/` tree per site — `raw/{inline,external,sourcemaps}/` · `beautified/{inline,external}/` · `ast/external/` + `ast/symbols.json` · `analysis/{inline,external}/` + `analysis/site-summary.md` · `findings/{endpoints,params,apis,secrets,gadgets,libraries}.jsonl` · `report.md` · `curl_commands.sh` · `logs/` (see §Outputs for the exact mandated tree).
- **DATA / RAG:** inputs = scope roots + optional auth (cookies/headers for authed-vs-unauthed diff). `refs/` corpus = secret regexes, dangerous-sink list, retire.js vuln-lib signatures, param-mining wordlist. Chains FROM host discovery; chains TO content-discovery (feeds `custom_list.txt` from `findings/endpoints.jsonl` + `findings/params.jsonl`) and the DOM-XSS agent (consumes `findings/gadgets.jsonl` + `findings/endpoints.jsonl`).
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
1. Enumerate JS sources (inline + files, lazy, historical, sourcemaps) · `katana -jc` / `gau` / `waymore` / `subjs` · `logs/js_sources.txt`
2. Fetch all JS via escalation ladder (see §Tools) · → · `raw/inline/`, `raw/external/` + `logs/fetch.log`
3. Pull & unpack sourcemaps where present · `sourcemapper` / `unwebpack-sourcemap` · `raw/sourcemaps/` (.map + restored sources)
4. Store + normalize: dedupe by hash, apply the §Outputs filename rules · `sha256` + `cp` · `raw/` (deduped, canonical filenames)
5. Deobfuscate / beautify minified — reuse the EXACT raw filename stem · `webcrack` → `js-beautify` · `beautified/inline/`, `beautified/external/`
6. Parse to AST — one AST per external file · `@babel/parser` (or `acorn`) · `ast/external/{name}.ast.json`
7. Build symbol table — every global, export, and the file+line where each is defined · `@babel/traverse` / `acorn-walk` · `ast/symbols.json`
8. Extract endpoints (read AST + beautified); tag state live/historical/unauthed · `jsluice urls` / `xnLinkFinder` · `findings/endpoints.jsonl`
9. Extract params + routes (admin, feature flags, interesting comments) · `jsluice` / `xnLinkFinder` + `grep` · `findings/params.jsonl`
10. Extract APIs, group by functionality, flag old versions · `grep` + `jq` · `findings/apis.jsonl`
11. Extract secrets (known-regex vs high-entropy) · `trufflehog` + `gitleaks` + `jsluice secrets` · `findings/secrets.jsonl`
12. Map gadgets & dangerous sinks (DOM sinks) · `semgrep` (`refs/dangerous_sinks.yaml`) + `grep` · `findings/gadgets.jsonl`
13. Library + framework/tech analysis (outdated + CVEs) · `retire.js` / `nuclei -t http/technologies` / `httpx -td` · `findings/libraries.jsonl`
14. Per-file notes — purpose, notable sinks, endpoints/params contributed, secrets; one per file · agent-authored from beautified + ast · `analysis/inline/{name}.md`, `analysis/external/{name}.md`
15. Site summary — auth flow, full API surface, framework/build/library stack, risk highlights · synth across all notes + findings · `analysis/site-summary.md`
16. Emit report + curl, derived from `findings/` (curl for every `endpoints.jsonl` row with state `live`|`unauthed`) · synth + `printf` · `report.md`, `curl_commands.sh`
17. /REVIEW SKILL · `review.md`

## Tools
- **Enumerate:** `katana` (`-jc -jsl`), `gau`, `waymore`, `subjs`/`getJS`, `hakrawler` (alt)
- **Fetch ladder** (ANTI-AUTOMATION — escalate only when the prior rung is blocked; see `_contract/anti-automation-ladder.md`):
  `webfetch` → `curl` (UA+headers+auth) → interceptor (mitmproxy/Caido, manual browse) → `chrome-devtools-mcp` (headless, capture Network, lazy-load) → `puppeteer`/`playwright` (scroll+trigger)
- **Sourcemaps:** `sourcemapper`, `unwebpack-sourcemap`
- **Deobfuscate:** `webcrack` (webpack unbundle), `js-beautify`, `prettier`
- **AST + symbols:** `@babel/parser` + `@babel/traverse` (alt: `acorn` + `acorn-walk`, `ast-grep`, `tree-sitter-cli`) — one AST per external file; symbol table = globals/exports + definition file+line
- **Endpoints/params:** `jsluice`, `xnLinkFinder`, `LinkFinder`; `arjun`/`x8` to actively confirm params
- **Secrets:** `trufflehog` (filesystem), `gitleaks` (dir), `jsluice secrets`, `secretfinder`/`mantra`
- **Libs/tech:** `retire.js`, `nuclei` (`http/exposures`, `http/technologies`, `javascript/`), `httpx -td`
- **Glue:** `jq`, `semgrep`, `ripgrep`
- **Findings (JSONL) assembly:** `node` / `jq` — emit one JSON object per line into `findings/*.jsonl`
- **Notes + summary:** authored by the agent (not a tool) — per-file `analysis/**/*.md` + `analysis/site-summary.md`

## Inputs
- `scope.txt` (roots/domains in scope)
- optional `auth.env` (`COOKIE=`, `HEADERS=`) → enables authed-vs-unauthed endpoint diff
- `refs/` (RAG): `secret_regexes.yaml`, `dangerous_sinks.yaml`, `retire_signatures.json`, `param_wordlist.txt`

## Outputs
A completed run produces **one directory per site** and MUST match this tree exactly:

```text
out/<site>/                         # e.g. out/app.target.com/, one per site
├── raw/
│   ├── inline/                     # one file per <script> block: {page-slug}.{index}.js
│   ├── external/                   # every .js fetched, ORIGINAL bytes, unmodified
│   └── sourcemaps/                 # .map files + restored original sources
├── beautified/
│   ├── inline/                     # SAME filenames as raw/inline/
│   └── external/                   # SAME filenames as raw/external/
├── ast/
│   ├── external/                   # {name}.ast.json per external file
│   └── symbols.json                # globals, exports, and where each is defined
├── analysis/
│   ├── inline/                     # {name}.md — one note per inline block
│   ├── external/                   # {name}.md — one note per JS file
│   └── site-summary.md             # cross-file: auth flow, API surface, stack
├── findings/                       # machine-readable, one JSON object per line
│   ├── endpoints.jsonl             # {url, method?, source_file, line, state: live|historical|unauthed}
│   ├── params.jsonl                # {name, context, source_file, line, likely_vuln: bool}
│   ├── apis.jsonl                  # {path, group, version?, source_file}
│   ├── secrets.jsonl               # {type, match_redacted, entropy?, source_file, line}
│   ├── gadgets.jsonl               # {sink, snippet, source_file, line}
│   └── libraries.jsonl             # {name, version, cves[], source_file}
└── logs/                           # one log per tool/action
```

All six `findings/*.jsonl` share the **one-object-per-line** convention — every line is a complete JSON
object matching the shape commented beside it above; keep them consistent.
`report.md` + `curl_commands.sh` are derived deliverables written at the **site root**
(`out/<site>/report.md`, `out/<site>/curl_commands.sh`); `logs/` also holds `js_sources.txt`.

### Filename rules (HARD)
- Inline: `{page-slug}.{index}.js`  (page-slug from the page URL, index = script order).
- External: keep the remote basename; on collision suffix with a short host/path hash.
- `beautified/*` and (where applicable) `ast/*` reuse the EXACT raw filename stem.

## Phases
- **Phase 1 (generic):** passive enumerate + historical + fetch + store + deobfuscate + parse AST + build symbol table.
- **Phase 2 (target-specific):** findings (endpoints/params/APIs/secrets/gadgets/libraries) + per-file notes + site-summary + report/curl.
