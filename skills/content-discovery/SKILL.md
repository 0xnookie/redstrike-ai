# Content Discovery

> TIER-1 recon feeder. Per live host: crawl + historical URLs + **custom wordlist building** +
> directory/file brute-force + parameter discovery. Builds a TARGET-SPECIFIC wordlist from OSINT +
> crawl + JS. ACTIVE → honors `_contract/roe-gate.md`. Emits NO findings → `review.md` only.

## Interview
- **STEPS:** ingest live hosts → crawl → historical URLs → BUILD custom wordlist (osint terms + crawl + js) → directory/file brute-force → parameter discovery → virtual-host/bucket check → consolidate → review.
- **TOOLS:** `katana`/`hakrawler`/`gospider` (crawl), `gau`/`waymore` (historical), `cewl` + synth (wordlist), `ffuf`/`feroxbuster`/`gobuster`/`dirsearch` (brute-force), `arjun`/`paramspider`/`x8` (params), `wafw00f` (WAF fingerprint). Tool-first — `_contract/tooling.md`.
- **GOAL:** Produce the content map per host — crawled + brute-forced endpoints, discovered params, and a **custom wordlist** — feeding js-analysis and the vuln agents. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `crawl.txt`, `endpoints.txt`, `params.txt`, `custom_wordlist.txt`, `content.json`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = `<engagement>/host-discovery/host_discovery.json` (live hosts) + `<engagement>/osint/terms.txt` + `js-analysis/out/<site>/findings/{endpoints,params}.jsonl` (if run) + `scope.yaml`. `refs/` = `content_discovery_refs.md`. Chains FROM `host-discovery`, `osint`; chains TO `js-analysis` + every vuln feeder (endpoints/params/wordlist). Canonical order: content-discovery PRECEDES js-analysis; the `js-analysis/*` inputs above are consumed ONLY on an OPTIONAL second enrichment pass, so recon stays acyclic.
- **DECOMPOSITION:** n/a (recon feeder). Includes wordlist building.

## Goal
Produce the content map + a target-specific wordlist. DONE = `checklist.md` `- [x]` · `review.md` PASS.

## What do we want
- Crawled URLs (spider, incl. JS-rendered) + historical URLs (Wayback/gau)
- A **custom wordlist** built from OSINT terms + crawled paths + JS strings (beats a generic list)
- Brute-forced directories/files (with the custom + a standard list)
- Discovered parameters (from crawl + active mining)

## Steps  (action · tool · output)
1. Ingest live hosts + osint terms · `jq host_discovery.json` + `terms.txt` · (seed)
2. Crawl each live host (passive + JS-aware) · `katana -jc`/`hakrawler` · `crawl.txt`
3. Historical URLs · `gau`/`waymore` · `crawl.txt` (merged)
4. **Build custom wordlist** (osint terms + crawl path-segments + js strings + a base list) · `cewl` + synth · `custom_wordlist.txt`
5. Directory/file brute-force (custom + standard list, rate-limited) · `ffuf`/`feroxbuster` · `endpoints.txt`
6. Parameter discovery (from crawl + active mining) · `arjun`/`x8` + `grep` · `params.txt`
7. Consolidate · synth · `content.json`
8. Emit summary · synth · `summary.md`
9. /REVIEW SKILL · `review.md`

## Tools
- `katana`/`hakrawler`/`gospider` (crawl), `gau`/`waymore` (historical), `cewl` + synth (wordlist), `ffuf`/`feroxbuster`/`gobuster`/`dirsearch`/`dirb` (brute-force), `arjun`/`paramspider`/`x8` (params), `wafw00f` (WAF fingerprint)
- **Tool-first rule + roster:** `_contract/tooling.md` — never hand-roll a crawler/brute-forcer when these exist.
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `<engagement>/host-discovery/host_discovery.json` (live hosts), `<engagement>/osint/terms.txt`
- `js-analysis/out/<site>/findings/{endpoints,params}.jsonl` (if already run), `scope.yaml`
- `refs/content_discovery_refs.md`

## Outputs
`crawl.txt` · `endpoints.txt` · `params.txt` · `custom_wordlist.txt` · `content.json` · `summary.md` · `logs/`

## Phases
- **Phase 1 (generic):** crawl + historical + custom-wordlist build.
- **Phase 2 (target-specific):** brute-force + parameter discovery + consolidation.

## Safety
Active crawling + brute-forcing — **rate-limit** (respect `scope.yaml` `rate_limit_rps`); in-scope hosts
only; no aggressive threading that could disrupt; honor `no_dos`. Prefer the custom wordlist (fewer, smarter
requests) over mega-lists on prod. Audit-log.
