# Shopware Agent — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Fingerprint
- [ ] Shopware confirmed + version pinned from ≥2 independent signals (`sw-*` headers, `Vary: sw-cache-hash`, `X-Symfony-Cache`, administration bundle, `/api/_info/version`, `/api/_info/openapi3.json`; white-box `composer.lock` `shopware/core`) — a single-signal guess is `tentative`, not a finding
- [ ] Upstream inputs consumed (host-discovery tech+version; js-analysis libraries/site-summary; source-audit composer.lock + Apache aliases when white-box)
- [ ] framework.json written (framework, version, signals[], confidence, debug_mode, image e.g. dockware)

## Surface
- [ ] Admin SPA `/admin` + Admin API `/api/*` (OAuth, 401 unauth) mapped
- [ ] Store API `/store-api/*` posture (`sw-access-key`; ACAO:* is by-design for the public key-gated API — not a CORS finding)
- [ ] `/api/_info/openapi3.json` + `/api/_info/swagger.html` auth state checked (unauth spec = disclosure → exposed-surface)
- [ ] Symfony profiler `/_profiler` + `/_wdt` + `X-Debug-Token` checked (debug mode?)
- [ ] account/checkout flows noted; active custom plugins enumerated (admin plugin API, else `cp-*`/theme JS)
- [ ] surface.json written

## Dev-image & default-cred posture
- [ ] Debug mode determined (`X-Debug-Token`/WDT ⇒ APP_ENV=dev)
- [ ] dockware exposed-tool set probed: `/adminer`, `/mailcatcher`+`/messages`, `/logs` (pimpmylog), `/_profiler/phpinfo`
- [ ] Default admin creds probed ONCE, lockout-aware: `POST /api/oauth/token` `admin:shopware` (200+Bearer ⇒ finding)

## Map
- [ ] Version → version-APPLICABLE Shopware CVEs (exact range; latest-patch check; mismatches dropped)
- [ ] Reachability assessed (CVE feature actually present/used; exposed tool actually reachable; creds actually accepted)
- [ ] Generic non-Shopware library CVEs left to cve-intelligence (de-dupe Symfony/guzzle/twig/dompdf/…)
- [ ] Exploit availability noted (advisory / PoC ref)
- [ ] cve_map.json written

## Confirm
- [ ] Benign confirmation per candidate (version banner + behaviour/header/body differential; ONE default-cred probe) — NO exploitation, NO mail/DB dump, NO protected-data exfil, secrets redacted
- [ ] Counterevidence applied (`_contract/counterevidence.md`): opposing case argued, each candidate closed confirmed/ruled-out/open-proof-gap

## Emit
- [ ] findings.json (dev-tool exposures + default creds + unauth OpenAPI + reachable version-matched CVEs; schema-valid; CVSS tempered by reachability; potential_severity when exposure/version-only; route-value→exposed-surface, secret-value→secrets de-dup honored)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
