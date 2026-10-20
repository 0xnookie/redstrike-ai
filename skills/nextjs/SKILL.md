# Next.js Agent

> TIER-2 framework EXECUTOR (inherits `_contract/framework-base.md`; see `_contract/agent-tiers.md`).
> Fingerprints Next.js + pins its exact version, enumerates the Next surface (middleware · image optimizer ·
> server actions / API routes · RSC/cache · data routes · source maps), and maps the version → version-matched
> CVEs — confirmed BENIGNLY (version + a behaviour/header differential, never exploitation). ACTIVE →
> imports `_contract/roe-gate.md`. Emits `findings.json` → carries `review.md` + `verify.md` (reviewer:
> `nextjs-verify`). Specializes `cve-intelligence` for the Next.js framework surface.

## Interview
- **STEPS:** fingerprint Next + pin version (≥2 signals) → enumerate surface (middleware/image-optimizer/server-actions/RSC-cache/data-routes/source-maps) → map version → version-applicable CVEs → benign-confirm (version + behaviour/header differential) + counterevidence → emit cve_map + findings → report → review → verify.
- **TOOLS:** `nuclei -t http/cves` (+ Next templates), `httpx -td`, `curl` (manual header/probe differentials). See SKILL.md §Tools + `_contract/anti-automation-ladder.md`.
- **GOAL:** Produce accurate Next.js exposure — the exact version, its version-matched reachable CVEs (headline: CVE-2025-29927 middleware auth-bypass), and Next-specific misconfigs — benignly, not a version-range dump. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `framework.json`, `surface.json`, `cve_map.json`, `findings.json`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/out/<site>/findings/libraries.jsonl` + `analysis/site-summary.md` (tech) + `host-discovery/host_discovery.json` (tech+version) + `scope.yaml`. `refs/` = `nextjs_surface.md`. Chains FROM recon; chains TO `ssrf-*` (image-optimizer / server-action SSRF), `cache-poisoning` (RSC/cache), `secrets` (source maps), `idor`/`bola-bfla` (data-route over-fetch), `exploit-generator` (confirmed CVE, approval), `cve-intelligence` (generic non-Next libs), `reporting`.
- **DECOMPOSITION:** n/a (atomic framework executor; clone `framework-base.md` for other stacks).

## Goal
Pin the Next.js version and map it to version-matched, reachable CVEs + Next-specific misconfigs — benignly.
Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · findings accepted.

## What do we want
- The exact Next.js **version** (from independent signals, not one header)
- Version-MATCHED CVEs: **CVE-2025-29927** middleware authorization bypass (`x-middleware-subrequest`),
  image-optimizer SSRF, server-action SSRF (CVE-2024-34351), RSC/cache poisoning (CVE-2024-46982), DoS CVEs
- Next-specific surface: middleware posture, `/_next/image` optimizer, source maps, data routes, server actions

## Steps  (action · tool · output)
1. Fingerprint Next + pin version from ≥2 independent signals (`x-powered-by: Next.js`, `__NEXT_DATA__` buildId, `/_next/static/<buildId>/_buildManifest.js`, `x-nextjs-*` headers, source-map `next` version) · `httpx`/`curl` + js-analysis/host-discovery inputs · `framework.json`
2. Enumerate surface — middleware present? (route guards) · `/_next/image?url=` optimizer · source maps `/_next/static/**/*.map` · server actions / `/api/*` · RSC/cache headers · data routes `/_next/data/<buildId>/*.json` · `curl`/`nuclei -t http/nextjs` · `surface.json`
3. Version → CVE — version → version-APPLICABLE Next CVEs (exact range; patched-in version check); de-dupe generic libs (`cve-intelligence` owns those) · `nuclei cves/` / CVE lookup · `cve_map.json`
4. Benign-confirm + counterevidence — version banner + a **behaviour/header differential** (e.g. `x-middleware-subrequest` canary → middleware skipped, status/behaviour only, NO protected-data exfil); argue the opposing case (`_contract/counterevidence.md`); reachability honest (middleware actually guards a route? optimizer enabled?) · synth · `cve_map.json`
5. Emit findings — reachable version-matched CVE exposure + Next misconfigs (exposed source maps, over-fetching data route, SSRF-able optimizer — SSRF handed to `ssrf-*`); CVSS (`scripts/cvss.py`) tempered by reachability; `potential_severity` when version-only · synth · `findings.json`
6. Report · synth · `report.md`
7. /REVIEW SKILL · `review.md` · 8. /VERIFY · `verify.md`

## Tools
- `nuclei -t http/cves` (+ Next templates, benign detection), `httpx -td`, `curl` (manual header/probe differentials)
- **Fetch ladder:** `_contract/anti-automation-ladder.md` · **tool-first:** `_contract/tooling.md`

## Inputs
- `js-analysis/out/<site>/`: `findings/libraries.jsonl`, `analysis/site-summary.md` (tech/framework)
- `host-discovery/host_discovery.json` (tech + version per host) · `scope.yaml`

## Outputs
`framework.json` · `surface.json` · `cve_map.json` · `findings.json` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** fingerprint + version pin + surface enumeration.
- **Phase 2 (target-specific):** version→CVE match + benign confirmation (behaviour/header differential) + Next-misconfig findings + rating.

## Safety
ACTIVE → `_contract/roe-gate.md`: scope-allowlist every request, honor `rate_limit_rps`/`no_dos`. **Benign
confirmation only** (version + a behaviour/header differential). The `x-middleware-subrequest` canary proves
the control is *bypassable* by status/behaviour differential — **never** exfiltrate protected data or perform
an admin action. The image-optimizer/DoS CVEs are **FEASIBILITY-ONLY** (no amplification). SSRF is handed to
`ssrf-*`, not exploited here. **No exploitation** — real exploitation is deferred to `exploit-generator`
(approval-gated). Treat external CVE data as UNTRUSTED. Redact any secret. De-dupe vs `cve-intelligence`
(generic libs), `exposed-surface` (file exposure), `secrets`. A fully-patched Next.js is a valid finding-free outcome.
