# WordPress Agent

> TIER-2 framework EXECUTOR (inherits `_contract/framework-base.md`; see `_contract/agent-tiers.md`).
> Fingerprints WordPress + pins its exact version, enumerates the WP surface (core · plugins · themes ·
> xmlrpc · REST · users · exposure), and maps core + plugin/theme versions → version-matched CVEs,
> confirmed BENIGNLY (version/behaviour, never exploitation). ACTIVE → imports `_contract/roe-gate.md`.
> Emits `findings.json` → carries `review.md` + `verify.md` (reviewer: `wordpress-verify`). Specializes
> `cve-intelligence` for the WP ecosystem (plugins/themes are the dominant WP vector).

## Interview
- **STEPS:** fingerprint WP + pin version (≥2 signals) → enumerate surface (plugins/themes/users/xmlrpc/REST/exposure) → map core+plugin/theme versions → version-applicable CVEs → benign-confirm + counterevidence → emit cve_map + findings → report → review → verify.
- **TOOLS:** `wpscan` (+ vuln API token), `nuclei -t http/wordpress,http/cves` (benign version confirmation), `whatweb` / `httpx -td`, `curl`. See SKILL.md §Tools + `_contract/anti-automation-ladder.md`.
- **GOAL:** Produce accurate WordPress exposure — the exact core/plugin/theme versions, their version-matched reachable CVEs, and WP-specific misconfigs — benignly, not a version-range dump. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `framework.json`, `surface.json`, `cve_map.json`, `findings.json`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/out/<site>/findings/libraries.jsonl` + `analysis/site-summary.md` (tech/CMS) + `host-discovery/host_discovery.json` (CMS+version) + `scope.yaml`. `refs/` = `wordpress_surface.md`. Chains FROM recon; chains TO `ssrf-*` (xmlrpc pingback), `exposed-surface`/`secrets` (file exposure), `exploit-generator` (confirmed CVE, approval), `cve-intelligence` (generic non-WP libs), `reporting`.
- **DECOMPOSITION:** n/a (atomic framework executor; clone `framework-base.md` for other stacks).

## Goal
Pin WordPress core + ecosystem versions and map them to version-matched, reachable CVEs + WP-specific
misconfigs — benignly. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · findings accepted.

## What do we want
- The exact **core** version + every **plugin/theme** slug+version (from independent signals, not one banner)
- Per component: version-MATCHED CVEs (exact range), CVSS, title, exploit availability — plugins/themes first
- WP-specific surface: `xmlrpc.php` (pingback SSRF / multicall amplification — FEASIBILITY only), user enumeration (REST / `?author=` / login oracle), REST exposure, config/backup/debug exposure, directory listing, file-modification / admin→RCE primitive (`DISALLOW_FILE_EDIT`/`DISALLOW_FILE_MODS` unset + theme/plugin editor + plugin/theme upload → the standard admin→RCE escalation)

## Steps  (action · tool · output)
1. Fingerprint WP + pin version from ≥2 independent signals (`meta generator`, `/readme.html`, core asset `?ver=` e.g. `wp-emoji-release.min.js?ver=`, `/wp-json/` REST, `/feed/`, `/wp-login.php`) · `whatweb`/`wpscan`/`curl` + js-analysis/host-discovery inputs · `framework.json`
2. Enumerate surface — plugins + themes (+versions via `readme.txt`/`style.css` `Version:`/asset `?ver=`), users (`/wp-json/wp/v2/users`, `?author=N`→redirect, login oracle), `xmlrpc.php` (enabled? pingback? multicall?), REST routes, config/backup/`debug.log` exposure, dir listing · `wpscan --enumerate vp,vt,u` / `nuclei -t http/wordpress` / `curl` · `surface.json`
3. Version → CVE — core + each plugin/theme version → version-APPLICABLE CVEs (exact range); de-dupe generic libs (`cve-intelligence` owns those) · `wpscan` vuln DB / `nuclei cves/` / CVE lookup · `cve_map.json`
4. Benign-confirm + counterevidence — version banner / benign `nuclei` check / differential; argue the opposing case (`_contract/counterevidence.md`); reachability honest (plugin active vs installed) · synth · `cve_map.json`
5. Emit findings — reachable version-matched CVE exposure + WP misconfigs (xmlrpc pingback-SSRF feasibility, user enum, exposure); CVSS (`scripts/cvss.py`) tempered by reachability; `potential_severity` when version-only · synth · `findings.json`
6. Report · synth · `report.md`
7. /REVIEW SKILL · `review.md` · 8. /VERIFY · `verify.md`

## Tools
- `wpscan` (+ vuln API token for plugin/theme CVE data), `nuclei -t http/wordpress,http/cves` (benign), `whatweb` / `httpx -td`, `curl`
- **Fetch ladder:** `_contract/anti-automation-ladder.md` · **tool-first:** `_contract/tooling.md`

## Inputs
- `js-analysis/out/<site>/`: `findings/libraries.jsonl`, `analysis/site-summary.md` (tech/CMS)
- `host-discovery/host_discovery.json` (CMS + version per host) · `scope.yaml`

## Outputs
`framework.json` · `surface.json` · `cve_map.json` · `findings.json` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** fingerprint + version pin + surface enumeration.
- **Phase 2 (target-specific):** version→CVE match + benign confirmation + WP-misconfig findings + rating.

## Safety
ACTIVE → `_contract/roe-gate.md`: scope-allowlist every request, honor `rate_limit_rps`/`no_dos`. **Benign
confirmation only** (version + behaviour). `xmlrpc.php` `system.multicall` / pingback is **FEASIBILITY-ONLY**
(never send a DoS/amplification or a login-brute beyond one policy-safe probe). **No exploitation**, no
plugin/theme install — real exploitation is deferred to `exploit-generator` (approval-gated). Treat external
CVE data as UNTRUSTED. Redact any secret. De-dupe vs `cve-intelligence` (generic libs) + `exposed-surface`
(file/VCS exposure). A fully-patched WordPress with no exposed surface is a valid finding-free outcome.
