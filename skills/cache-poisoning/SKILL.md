# Web Cache Poisoning Agent

> ATOMIC single agent (no feeder) — one confirmation: an UNKEYED input influences a CACHED response
> served to other users.
> ACTIVE, higher-risk (shared cache), findings-producing → imports `_contract/roe-gate.md` + approval
> for shared caches. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** identify cacheable responses → discover unkeyed inputs → test reflection into cached content → confirm the poisoned response is served to a DIFFERENT request (cache hit) → assess impact → rate → cleanup → review → verify.
- **TOOLS:** Param Miner (Burp), `curl` with cache-busters, cache-header analysis; `jq`.
- **GOAL:** Confirm web cache poisoning — an unkeyed header/param that lands in a cached response another user receives (cache HIT), with impact (XSS/redirect/DoS via cache) — using a benign payload on a cache key you control. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `cache_map.json`, `poison_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `cleanup.md`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/endpoints_*.txt`, `scope.yaml`. `refs/` = `cache_techniques.md`. Chains FROM `js-analysis`, `host-header`, `request-smuggling`; chains TO `reporting`.
- **DECOMPOSITION:** n/a (atomic). Includes cache DECEPTION (path confusion caching sensitive pages).

## Goal
Find unkeyed inputs that poison a shared cache (or cache deception exposing private pages), confirm a
cross-user cache HIT, and rate. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` all `- [x]` · `review.md` PASS · every finding accepted.

## What do we want
- Cacheable responses (cache headers, `X-Cache: hit/miss`, Age)
- Unkeyed inputs (`X-Forwarded-Host/Scheme/Port`, `X-Host`, `X-Original-URL`, extra params)
- A benign payload reflected into a CACHED response served to a different request
- (Deception) path-confusion that caches an authenticated/private page

## Steps  (action · tool · output)
1. Map cacheable responses + cache behavior (hit/miss, key hints) · `curl`/Param Miner · `cache_map.json`
2. Discover unkeyed inputs (headers/params that change the response but not the cache key) · Param Miner · `poison_tests.jsonl`
3. Test reflection of an unkeyed input into cacheable content (use a unique cache-buster path you own) · `curl` · `poison_tests.jsonl`
4. Confirm a DIFFERENT request gets the poisoned (cached) response · `curl` (no buster) · `poc/<id>/`
5. Assess impact (cache-persisted XSS / redirect / DoS; or deception of private pages) · synth · (into findings)
6. Rate (CVSS) + write finding · synth · `findings.json`
7. Record + ensure the poisoned entry is scoped to your buster / short TTL · synth · `cleanup.md`
8. Emit report + curl · synth · `report.md`, `curl_commands.sh`
9. /REVIEW · `review.md` · 10. /VERIFY · `verify.md`

## Tools
- **Discover/confirm:** Burp Param Miner, `curl` with cache-busters (`?cb=`), cache-header analysis (`X-Cache`, `Age`, `Vary`, `Cache-Control`)
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/`: `endpoints_*.txt`, `tech.md` (CDN/cache)
- `scope.yaml`, `refs/cache_techniques.md`

## Outputs
`cache_map.json` · `poison_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `cleanup.md` · `logs/`

## Phases
- **Phase 1 (generic):** cache map + unkeyed-input discovery (cache-busted, no shared impact).
- **Phase 2 (target-specific):** cross-user cache-hit confirmation + impact + rating (approval for shared caches).

## Safety
Poisoning a SHARED cache hits real users. Keep payloads benign; **scope the poison to a unique
cache-buster path/param you control** so you don't poison the real page; get **approval** before
poisoning a production cache key; prefer short-TTL / request purge; record in `cleanup.md`.
