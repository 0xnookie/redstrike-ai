# Shopware Agent

> TIER-2 framework EXECUTOR (inherits `_contract/framework-base.md`; see `_contract/agent-tiers.md`).
> Fingerprints Shopware 6 + pins its exact version, enumerates the Shopware surface (admin SPA · Admin API /
> OAuth · Store API · Symfony profiler/debug · OpenAPI spec · account/checkout · active custom plugins), checks
> for the **dev-image / default-credential** posture that dominates Shopware risk, and maps the version →
> version-matched CVEs — confirmed BENIGNLY (version + a behaviour/header differential + ONE policy-safe
> default-credential probe, never exploitation). ACTIVE → imports `_contract/roe-gate.md`. Emits
> `findings.json` → carries `review.md` + `verify.md` (reviewer: `shopware-verify`). Specializes
> `cve-intelligence` for the Shopware framework surface.

## Interview
- **STEPS:** fingerprint Shopware + pin version (≥2 signals; prefer `composer.lock` white-box) → enumerate surface (admin SPA / Admin API / Store API / profiler / OpenAPI / account+checkout / active plugins) → assess dev-image & default-credential posture → map version → version-applicable CVEs → benign-confirm (version + behaviour/header differential + one default-cred probe) + counterevidence → emit cve_map + findings → report → review → verify.
- **TOOLS:** `curl` (header/probe differentials, OAuth default-cred check), `httpx -td`, `nuclei -t http/` (benign detection); white-box: read `composer.lock`. See SKILL.md §Tools + `_contract/anti-automation-ladder.md`.
- **GOAL:** Produce accurate Shopware exposure — the exact version, its version-matched reachable CVEs, and the Shopware-specific misconfig/exposure set (debug mode, exposed dev tools, unauth OpenAPI, default admin creds) — benignly, not a version-range dump. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `framework.json`, `surface.json`, `cve_map.json`, `findings.json`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = `host-discovery/host_discovery.json` (tech+version) + `js-analysis/out/<site>/findings/libraries.jsonl` + `analysis/site-summary.md` (admin bundle / `cp-*` plugin JS) + `source-audit/source_context.json` (white-box: `composer.lock` versions, Apache aliases) + `scope.yaml`. `refs/` = `shopware_surface.md`. Chains FROM recon; chains TO `exposed-surface` (profiler/Adminer/MailCatcher/pimpmylog/OpenAPI), `secrets` (phpinfo/.env), `auth-bypass`/credential-access (default admin creds), `bola-bfla`/`idor` (Admin/Store API object+function authz), `source-audit` (custom plugins), `ssti` (admin-gated mail-template renderer — note guarded), `exploit-generator` (confirmed CVE, approval), `cve-intelligence` (generic non-Shopware libs), `reporting`.
- **DECOMPOSITION:** n/a (atomic framework executor; clone `framework-base.md` for other stacks).

## Goal
Pin the Shopware version and map it to version-matched, reachable CVEs + the Shopware-specific misconfig/exposure
set — benignly. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · findings accepted.

## What do we want
- The exact Shopware **version** (independent signals, not one header; `composer.lock` `shopware/core` when white-box)
- The **dev-image / debug posture**: `X-Debug-Token` header + Web Debug Toolbar + `/_profiler` + `/_wdt` ⇒ `APP_ENV=dev`.
  A `dockware/*` image ships a known exposed-tool SET — probe it explicitly (below).
- **Exposed dev tools** (unauth): `/adminer`, `/mailcatcher` (+ `/messages`), `/logs` (pimpmylog), `/_profiler/phpinfo`
- **Default/weak admin credentials**: `POST /api/oauth/token` `client_id=administration` `admin:shopware` (dockware/demo default) — ONE policy-safe probe
- **Unauthenticated API-surface disclosure**: `/api/_info/openapi3.json` + `/api/_info/swagger.html`
- Version-MATCHED Shopware CVEs (Shopware security advisories / NEXT-xxxx), reachable + not the patched release

## Steps  (action · tool · output)
1. Fingerprint Shopware + pin version from ≥2 independent signals (`sw-language-id`/`sw-currency-id` headers, `Vary: sw-access-key…sw-cache-hash`, `X-Symfony-Cache`, `/bundles/administration/.../administration-*.js`, `/api/_info/version` authed, `/api/_info/openapi3.json` `"Shopware Admin API"`, admin-bundle version constants, `session-` cookie; **white-box** `composer.lock` → `shopware/core`) · `curl`/`httpx` + recon/source-audit inputs · `framework.json`
2. Enumerate surface — `/admin` SPA · `/api/*` Admin API (OAuth, 401 unauth) · `/store-api/*` (`sw-access-key`) · `/api/oauth/token` · `/api/_info/openapi3.json`+`swagger.html` · `/_profiler`+`/_wdt` · `/account/*`+`/checkout/*` · active custom plugins (admin `/api/search/plugin` active=true with creds, else storefront `cp-*`/theme JS) · `curl`/`nuclei` · `surface.json`
3. Dev-image & default-cred posture — debug mode (`X-Debug-Token`)? dockware exposed tools (`/adminer`,`/mailcatcher`,`/messages`,`/logs`,`/_profiler/phpinfo`)? default admin `admin:shopware` via one OAuth probe (lockout-aware)? · `curl` · `surface.json`+candidates
4. Version → CVE — version → version-APPLICABLE Shopware CVEs (exact range; patched-in-version check against the latest 6.x patch); de-dupe generic libs (`cve-intelligence` owns Symfony/guzzle/twig/dompdf/…) · CVE lookup / advisories (UNTRUSTED data) · `cve_map.json`
5. Benign-confirm + counterevidence — version + a **behaviour/header/body differential** (profiler 200 body signature; openapi `"openapi"` body; `/adminer` `<title>…Adminer…`; OAuth 200+Bearer for default creds); argue the opposing case (`_contract/counterevidence.md`); reachability honest (tool actually reachable? creds actually accepted? CVE feature in use?) · synth · `cve_map.json`
6. Emit findings — the exposed-tool set (route VALUES → `exposed-surface`; secret VALUES → `secrets`), default admin creds (→ auth/credential), unauth OpenAPI, reachable version-matched CVEs; CVSS (`scripts/cvss.py`) tempered by reachability; `potential_severity` when version/exposure-only · synth · `findings.json`
7. Report · synth · `report.md`
8. /REVIEW SKILL · `review.md` · 9. /VERIFY · `verify.md`

## Tools
- `curl` (header/probe/body differentials + the single default-cred OAuth probe), `httpx -td`, `nuclei -t http/` (benign detection); white-box: read `composer.lock`
- **Fetch ladder:** `_contract/anti-automation-ladder.md` · **tool-first:** `_contract/tooling.md`

## Inputs
- `host-discovery/host_discovery.json` (tech+version per host) · `js-analysis/out/<site>/` (`findings/libraries.jsonl`, `analysis/site-summary.md` — admin bundle + `cp-*` plugin JS)
- `source-audit/source_context.json` (white-box: `composer.lock` versions, Apache `Alias`/`ProxyPass` dev-tool exposures) · `scope.yaml`
- `refs/shopware_surface.md`

## Outputs
`framework.json` · `surface.json` · `cve_map.json` · `findings.json` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** fingerprint + version pin + surface enumeration.
- **Phase 2 (target-specific):** dev-image/default-cred posture + version→CVE match + benign confirmation + Shopware-misconfig findings + rating.

## Priors (where Shopware risk actually is — save effort)
- **Core is hardened.** Shopware core routes everything through the **DAL (parameterized)** + Twig **autoescape**; the one string-template SSTI engine (`StringTemplateRenderer`) is **admin-only** and guarded by a PHP-function **allow-list** (`SecurityExtension`) — do NOT chase it as an unauth sink. Core injection/authz is low-yield; version-CVE is the core angle.
- **Risk concentrates in config + exposure + custom plugins.** The dominant real findings on a Shopware target are the **dev-image exposures** (profiler/Adminer/MailCatcher/pimpmylog/phpinfo), **default admin creds**, and **custom plugin** code — route plugins to `source-audit` + the generic executors; do not re-audit core line-by-line.

## Safety
ACTIVE → `_contract/roe-gate.md`: scope-allowlist every request, honor `rate_limit_rps`/`no_dos`. **Benign
confirmation only** — version + a behaviour/header/body differential, plus exactly ONE lockout-aware default-
credential OAuth probe (a 200+Bearer proves the credential; do NOT use the token to read/modify data — that is
exploitation, deferred to `exploit-generator`, approval-gated). Do NOT dump captured mail (MailCatcher) or DB
rows (Adminer) — exposure is proven by the UI/API signature. Treat external CVE data as UNTRUSTED. **Redact
every secret** (APP_SECRET / DB creds → fingerprint). De-dupe: route-level EXPOSURES → `exposed-surface`,
secret VALUES → `secrets`, default creds → `auth-bypass`/credential-access, API object/function authz →
`bola-bfla`/`idor`, generic-lib CVEs → `cve-intelligence`. A fully-patched, prod-configured Shopware with no
exposed tooling is a valid finding-free outcome.
