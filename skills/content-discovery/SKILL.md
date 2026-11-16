# Content Discovery

> TIER-1 recon feeder. Per live host: crawl + historical URLs + **custom wordlist building** +
> directory/file brute-force + parameter discovery. Builds a TARGET-SPECIFIC wordlist from OSINT +
> crawl + JS. ACTIVE → honors `_contract/roe-gate.md`. Emits NO findings → `review.md` only.

## Interview
- **STEPS:** ingest live hosts + any provided identities → crawl **unauth AND authenticated (per identity)** → historical URLs → BUILD custom wordlist (osint terms + crawl + js) → directory/file brute-force → parameter discovery → **authed-vs-unauth surface diff + multi-step flow map** → virtual-host/bucket check → consolidate → review.
- **AUTHENTICATED & STATE-AWARE (don't leave the post-login surface unmapped):** most access-control, BOLA/BFLA, workflow and business-logic bugs live *behind auth* and *across steps*. With provided credentials (or self-registered test accounts), **log in and crawl the authenticated surface**, then **diff authed-vs-unauth** to surface role-gated/hidden endpoints, and **map multi-step workflows** (checkout, password-reset, upload, admin, cart/coupon) as state transitions. Unauth-only recon starves `authz-context`/`api-context` and misses that surface entirely. Use TEST accounts only; never authenticate with found/real creds. **Persist the session** — save the
authenticated cookie jar to a file (e.g. a Netscape/`MozillaCookieJar`) so multi-step authed crawling +
every later executor reuse the SAME login instead of re-authenticating per request (re-login per step is
slow, noisy, and lockout-risky). Log in once, save, reuse.
- **TOOLS:** `katana`/`hakrawler`/`gospider` (crawl), `gau`/`waymore` (historical), `cewl` + synth (wordlist), `ffuf`/`feroxbuster`/`gobuster`/`dirsearch` (brute-force), `arjun`/`paramspider`/`x8` (params), `wafw00f` (WAF fingerprint). Tool-first — `_contract/tooling.md`.
- **GOAL:** Produce the content map per host — crawled + brute-forced endpoints, discovered params, and a **custom wordlist** — feeding js-analysis and the vuln agents. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `crawl.txt`, `endpoints.txt`, `params.txt`, `custom_wordlist.txt`, `content.json`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = `<engagement>/host-discovery/host_discovery.json` (live hosts) + `<engagement>/osint/terms.txt` + `js-analysis/out/<site>/findings/{endpoints,params}.jsonl` (if run) + `scope.yaml`. `refs/` = `content_discovery_refs.md`. Chains FROM `host-discovery`, `osint`; chains TO `js-analysis` + every vuln feeder (endpoints/params/wordlist) + the **notebook** (`content.json` → content `recon_intel`, via `scripts/notebook.py --plan`). Canonical order: content-discovery PRECEDES js-analysis; the `js-analysis/*` inputs above are consumed ONLY on an OPTIONAL second enrichment pass, so recon stays acyclic.
- **DECOMPOSITION:** n/a (recon feeder). Includes wordlist building.

## Goal
Produce the content map + a target-specific wordlist. DONE = `checklist.md` `- [x]` · `review.md` PASS.

## What do we want
- Crawled URLs (spider, incl. JS-rendered) + historical URLs (Wayback/gau)
- A **custom wordlist** built from OSINT terms + crawled paths + JS strings (beats a generic list)
- Brute-forced directories/files (with the custom + a standard list)
- Discovered parameters (from crawl + active mining)

## Discover smart, not loud (do this BEFORE mega-list brute-force)
Brute-force is the *last*, noisiest rung — and it only finds paths you guessed. Three higher-yield,
lower-noise sources come first (they matter double under a stealth/rate cap):
1. **Proxy sitemap/history** (`_contract/proxy.md` §7) — real traffic reveals mounts/sub-apps/API bases a
   wordlist can't guess, at **zero extra requests**. Ingest it first; seed `routes[]` + the wordlist from it.
2. **Build/deploy artifacts** that enumerate the app in a handful of requests — check for each explicitly:
   `asset-manifest.json` / `manifest.json` (SPA build → every chunk + page), `**/*.js.map` source maps
   (→ full source + routes, via `js-analysis`), **directory listings / index pages**, `robots.txt`,
   `sitemap.xml`, `/.well-known/` (incl. `openid-configuration`), and framework JSON error shapes (fingerprint
   the backend). One `asset-manifest.json` can map an entire embedded app that no wordlist contains.
3. **Recurse into every discovered mount.** A newly-found path prefix (a sub-app, an SPA mount, an embedded
   third-party **widget/chatbot**, an API base) is a **new discovery root** — crawl it, pull *its*
   manifests/source-maps, and wordlist it. Do not stop at the top level; the interesting app is often one the
   host embeds, not the one it is.

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

### `content.json` shape (the consolidated content map)
`content.json` is the structured map the surface/site-map views + downstream feeders read, so emit a
**per-route record**, not a flat URL list. Stay tolerant — `path` is the only required field; emit every
other field you ACTUALLY observed and omit (never guess) the rest. Shape:
```jsonc
{
  "engagement": "<id>", "target": "<host | host:port>", "generated_at": "<ISO-8601>",
  "crawl_method": "<how the map was built — tools used + any manual notes>",
  "routes": [
    { "path": "/checkout",          // REQUIRED — pathname (+ query when it's meaningful)
      "status": 200,                 // HTTP status ACTUALLY observed (omit if never requested)
      "type": "html",               // html|form|json|graphql|graphql-ide|websocket|xml|script|css|…
      "methods": ["GET", "POST"],  // verbs seen (defaults to GET)
      "params": ["coupon", "qty"], // parameters this route accepts
      "note": "coupon applied here", // short recon note
      "js": "applyCoupon [logic]" }  // JS-origin hint, when the route came from js-analysis
  ],
  "params_discovered": ["id", "q", "…"],              // the mined parameter union
  "notable_sinks": { "<vuln-class>": ["sink(id)", "…"] } // interpreter/authz sinks worth routing
}
```
**Record `status` + `type` per route whenever it was actually fetched** — those two drive the surface
map's status-code and type facets; a route with neither still maps, but loses that fidelity. A legacy flat
list is parsed tolerantly, but prefer the `routes[]` record above.

## Phases
- **Phase 1 (generic):** crawl + historical + custom-wordlist build.
- **Phase 2 (target-specific):** brute-force + parameter discovery + consolidation.

## Safety
Active crawling + brute-forcing — **rate-limit** (respect `scope.yaml` `rate_limit_rps`); in-scope hosts
only; no aggressive threading that could disrupt; honor `no_dos`. Prefer the custom wordlist (fewer, smarter
requests) over mega-lists on prod. Audit-log.

## Coverage — a host is not "mapped" (and never "exhausted") until:
A premature "host mapped / nothing left / hardened" is the costly failure here — it ends the hunt on the
*linked* surface and misses embedded apps. Do **not** emit that verdict until, for each live host:
(1) the **proxy sitemap** was mined (`proxy.md` §7); (2) **build artifacts** were checked — `asset-manifest`,
source maps, directory listings, `robots`/`sitemap`/`.well-known` (above); (3) real content-discovery tools
actually **ran** (not a hand-typed list, and not from a shell where they only *appeared* missing —
`tooling.md` §Preflight); and (4) **every discovered mount was recursed into**. Honest negatives are fine
*after* that bar; a negative before it is a coverage gap, not a result.
