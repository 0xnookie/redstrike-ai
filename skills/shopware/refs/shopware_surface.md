# Shopware surface & fingerprint recipe

Benign, read-only probes (honor scope + rate limit). `B` = base URL.

## Fingerprint (pin version from ≥2 signals)
- **Headers (storefront `/`):** `sw-language-id`, `sw-currency-id`, `Vary: sw-access-key,...,sw-cache-hash`, `X-Symfony-Cache`, `Set-Cookie: session-=`. Any 2 ⇒ Shopware 6.
- **Debug marker:** `X-Debug-Token` / `X-Debug-Token-Link: .../_profiler/<tok>` ⇒ `APP_ENV=dev` (debug mode ON).
- **Admin SPA:** `GET /admin` → `/bundles/administration/administration/assets/administration-*.js` (version constants `6.x.x.x` inside).
- **Admin API:** `GET /api/_info/version` → `{"version":"6.x.x.x"}` (needs OAuth; 401 unauth confirms the API). `GET /api/_info/openapi3.json` → `"openapi"` + `"Shopware Admin API"` (often unauth — a disclosure finding too).
- **Store API:** `/store-api/*` → 401 without `sw-access-key`.
- **White-box (preferred, exact):** `composer.lock` → `shopware/core` version; `.env` → `APP_ENV`, `DATABASE_URL`, `APP_SECRET`.

## Version currency
Shopware patches as `6.<minor>.<patch>.<build>` (e.g. 6.7.16.0). Check the pinned version against the latest
6.x release + the most recent security advisory (NEXT-xxxx / CVE). "Current patch" ⇒ no version-CVE finding;
deps go to `cve-intelligence` (Symfony/guzzle/twig/dompdf via `composer.lock`).

## Dev-image / dockware exposed-tool set (the dominant real risk)
When debug mode is ON (or the image is `dockware/*`), probe these UNAUTH (body signature, not bare status):
| Path | Signature | Finding → |
|------|-----------|-----------|
| `/_profiler/latest`, `/_profiler/<tok>` | Symfony Profiler panels | exposed-surface (debug mode) |
| `/_profiler/phpinfo` | phpinfo(); `$_ENV` APP_SECRET/DATABASE_URL | secrets (redact) + exposed-surface |
| `/_wdt/*` | Web Debug Toolbar assets | exposed-surface |
| `/adminer`, `/adminer/` | `<title>…Adminer…</title>` DB login | exposed-surface (DB UI) |
| `/mailcatcher` + `/messages` | `<title>MailCatcher</title>`; `/messages` JSON mail list | exposed-surface (reset-link interception) |
| `/logs`, `/logs/` | pimpmylog `Dockware Logs` (dev.log/access/error) | exposed-surface |
Soft-404 baseline: unknown storefront paths return **404** with a large (~400KB) themed body — distinct in
status + size + `Server` header from the real `200` tool pages.

## Default / weak admin credentials (ONE lockout-aware probe)
```
curl -s -X POST "$B/api/oauth/token" -H 'Content-Type: application/json' \
  -d '{"grant_type":"password","client_id":"administration","username":"admin","password":"shopware"}'
```
`200` + `{"token_type":"Bearer","access_token":...}` ⇒ default-cred finding (full admin). Do NOT reuse the
token to read/modify data (that is exploitation → `exploit-generator`, approval-gated). `admin:shopware` is the
dockware/demo default; keep the probe set tiny + policy-safe (no spraying, no lockout risk).

## Store/Admin API authz (hand off, don't exploit here)
- `/store-api/*` is `sw-access-key`-gated and intentionally `ACAO:*` (public, credential-less) — NOT a CORS finding.
- Admin API `/api/*` + `/api/_action/*` (675+ ops in the OpenAPI spec) → object/function authz testing is
  `bola-bfla`/`idor` with ≥2 identities, not this skill.

## Custom plugins
Enumerate the ACTIVE set first (admin `POST /api/search/plugin` `{"filter":[{"type":"equals","field":"active","value":true}]}`
with creds, else storefront `cp-*`/theme JS in `js-analysis`). Route custom-plugin CODE to `source-audit` +
the generic executors — do NOT audit Shopware core line-by-line (DAL-parameterized + Twig-autoescaped +
`SecurityExtension` allow-list make it low-yield).
