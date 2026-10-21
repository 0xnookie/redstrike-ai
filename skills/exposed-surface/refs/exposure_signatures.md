# Exposed-surface — confirmation signatures, tool invocations, severity, de-dup routing
# A hit is a FINDING only when the response BODY matches a signature below AND a random control path does
# not (soft-404 / wildcard ruled out). Status code alone proves nothing. GET/HEAD only, in scope.

## Establish the soft-404 baseline FIRST
`ffuf ... -ac` (auto-calibrate) or probe `https://HOST/<random-32hex>` and record its code/size/words.
Filter anything that matches the baseline. SPAs/WAFs return 200 for everything — calibrate per host.

## Signatures (resource → body must contain)
| Resource | Body signature (literal / regex) | Severity if present |
|---|---|---|
| `/.git/HEAD` | `^ref: refs/` | Git exposed → High if objects walkable |
| `/.git/config` | `[core]` + `repositoryformatversion` | High (remote URL may embed creds) |
| `/.svn/wc.db`, `/.svn/entries` | SQLite magic `SQLite format 3` / `dir` entry | High |
| `.env` | `^[A-Z0-9_]+=` lines (`APP_KEY=`, `DB_PASSWORD=`) | Critical if live creds |
| `wp-config.php` (raw) | `DB_PASSWORD`, `define(` | Critical |
| `*.sql` / `dump.sql` | `INSERT INTO` / `CREATE TABLE` / `-- MySQL dump` | Critical (data) |
| backups `*.zip/.tar.gz/.bak/~/.old/.swp` | archive magic `PK\x03\x04` / `\x1f\x8b`, or source text | High |
| directory listing | `<title>Index of /` / `Directory listing for` | Low–Medium (tree-dependent) |
| `phpinfo`/`info.php` | `<title>PHP ` + `phpinfo()` table | Medium (full env leak) |
| `server-status` (Apache) | `Apache Server Status for` | Medium |
| Spring `/actuator/env` | JSON `"activeProfiles"` / `"propertySources"` | High (→ `/heapdump` = creds) |
| `/actuator/heapdump` | binary `HPROF` magic | Critical (memory → secrets) |
| `/metrics` (Prometheus) | `# HELP` / `# TYPE` | Low–Medium |
| `.DS_Store` | magic `\x00\x00\x00\x01Bud1` | Low (dir names leak) |
| swagger/openapi | `"swagger":` / `"openapi":` + internal paths | Info–Medium (internal API map) |
| exposed admin panel | login form + product banner, reachable unauth | Medium (pre-auth surface) |

## Tool invocations (Linux / Kali — tool-first, see _contract/tooling.md)
```bash
# Directory/file fuzz (pick one; ffuf default). -ac auto-calibrates the soft-404 baseline.
ffuf -w refs/sensitive_paths.txt:FUZZ -u https://HOST/FUZZ -mc all -ac -rate <rps> -of json -o fuzz_raw.json
feroxbuster -u https://HOST -w refs/sensitive_paths.txt --rate-limit <rps> --json -o fuzz_raw.jsonl
gobuster dir -u https://HOST -w refs/sensitive_paths.txt -b 404,403 -q -o gobuster.txt
dirsearch -u https://HOST -w refs/sensitive_paths.txt --format=jsonl -o dirsearch.jsonl

# Templated exposures (info leak / misconfig / panels / backups)
# detection-only: scope to exposure dirs AND exclude active-exploit classes (-etags). NEVER -tags <product> (pulls CVE exploit templates that fire real RCE, crossing the approval gate).
nuclei -u https://HOST -t http/exposures/ -t http/misconfiguration/ -t http/exposed-panels/ -t http/backups/ -etags rce,intrusive,dos,oast -rl <rps> -jsonl -o nuclei.jsonl

# Fingerprint (tune lists + pace)
wafw00f https://HOST ; httpx -u https://HOST -td -sc -title -json

# Parameter discovery (surface only → route injection to the vuln agents)
arjun -u https://HOST/endpoint -oJ params.json ; paramspider -d HOST

# VCS: prove reconstructability BENIGNLY — do NOT bulk-dump a live repo
curl -s https://HOST/.git/HEAD        # expect: ref: refs/heads/...
# git-dumper only against an AUTHORIZED lab copy to demonstrate full reconstruction
```

## Benign-proof rule (roe-gate)
Prove exposure with ONE signature read. Do NOT mirror `/.git`, download a whole `.sql`/backup, or pull
`/actuator/heapdump` in bulk — note that reconstruction/extraction is possible and stop. Redact any secret
value to a fingerprint (first 4 + last 4, length, type) in `evidence/`.

## De-dup routing (avoid double-reporting)
- Live **secret value** in an exposed file → report the *exposure* here; hand the secret to **`secrets`** for liveness/impact (don't re-validate).
- Missing/weak **security header** → **`security-headers`**.
- Forced-browsing to an **authz-protected** resource (needs role matrix / ≥2 identities) → **`privesc`**.
- An exposed **param that injects** (SQLi/XSS/SSRF/LFI…) → the matching vuln agent; this skill flags the surface only.
- Dangling subdomain / claimable resource → **`subdomain-takeover`**.

---

## Extended arsenal — VCS metadata beyond /.git

| Resource | Body signature | Severity |
|---|---|---|
| `/.git/logs/HEAD` | `^[0-9a-f]{40} [0-9a-f]{40} ` + author line | High (reflog → more commits) |
| `/.git/index` | magic `DIRC` (`\x44\x49\x52\x43`) | High (tracked-file list) |
| `/.git/packed-refs` | `# pack-refs with:` | Medium (ref names) |
| `/.gitignore`, `/.git/COMMIT_EDITMSG` | path globs / commit text | Low (structure leak) |
| `/.hg/requires`, `/.hg/store/00manifest.i` | `revlogv1` / `dotencode`, or binary revlog | High (Mercurial repo) |
| `/.bzr/branch-format` | `Bazaar-NG meta directory` | High (Bazaar repo) |
| `/CVS/Entries`, `/CVS/Root` | `/<file>/<rev>/` lines / `:pserver:` | Medium |

---

## Extended arsenal — config & credential-file signatures

| Resource | Body signature | Severity |
|---|---|---|
| `appsettings.json`, `appsettings.*.json` | `"ConnectionStrings"` / `"Logging"` | Critical if conn-string live |
| `web.config` | `<configuration>` + `<connectionStrings>` | Critical |
| `application.properties`, `application.yml` | `spring.datasource.*` / `password:` | Critical |
| `settings.py` (Django) | `SECRET_KEY =` / `DATABASES =` | Critical |
| `config.php`, `configuration.php` | `define('DB_` / `$db` vars | Critical |
| `.npmrc` / `.pypirc` / `.netrc` | `_authToken=` / `[pypi]` / `machine … password` | High (registry/token) |
| `.dockercfg`, `.docker/config.json` | `"auths"` + base64 `"auth"` | High (registry creds) |
| `.aws/credentials` / `.s3cfg` / `.boto` | `aws_access_key_id` / `[default]` | Critical |
| kubeconfig (`.kube/config`) | `apiVersion: v1` + `clusters:` + `token:` | Critical |
| `*.tfstate` (Terraform) | `"terraform_version"` + `"resources"` | High (state → secrets) |
| `*.pem` / `id_rsa` / `*.key` | `-----BEGIN` … `PRIVATE KEY-----` (RSA/OPENSSH/EC) | Critical |

---

## Extended arsenal — framework debug consoles & actuator panels

| Resource | Body signature | Severity |
|---|---|---|
| Werkzeug / Flask debugger | `Traceback (most recent call last)` + `__debugger__` / interactive console | Critical (PIN-gated RCE) |
| Django `DEBUG=True` page | `You're seeing this error because` + `Request Method:` | High (settings/stack leak) |
| Rails exception page | `Full Trace` + `app/controllers` paths | Medium |
| Symfony `/_profiler` | `Symfony Profiler` | High (requests/config) |
| Laravel Ignition | `"ignition"` / `Illuminate\\` in trace | High (→ known RCE chains) |
| Spring `/actuator` index | JSON `"_links"` + `"health"`, `"env"` | Medium (enum the rest) |
| `/actuator/{beans,mappings,configprops,threaddump,loggers,httptrace}` | the respective JSON keys | Medium–High |
| Next.js `/_next/`, `__NEXT_DATA__` | `"buildId"` / `"props"` | Low (internal paths) |

---

## Extended arsenal — API-doc, source-map & build-artifact signatures

| Resource | Body signature | Severity |
|---|---|---|
| `swagger-ui.html`, `/swagger` | `swagger-ui` + `SwaggerUIBundle` | Info–Medium (API map) |
| `/v2/api-docs`, `/v3/api-docs`, `/openapi.json` | `"paths":` + `"components"` / `"definitions"` | Info–Medium |
| ReDoc page | `redoc` + `spec-url` | Info |
| GraphQL introspection | `"__schema"` / `"queryType"` in the POST response | Medium (→ `graphql`) |
| `*.js.map`, `*.css.map` | `"version":3` + `"sources"` + `"mappings"` | Medium (original source) |
| webpack `stats.json` / `manifest.json` | `"chunks"` / `"assetsByChunkName"` | Low–Medium |
| dep manifests `package.json` / `composer.lock` / `requirements.txt` / `yarn.lock` / `Gemfile.lock` | pinned name+version list | Low (versions → `cve-intelligence`) |

---

## Extended arsenal — CI/CD & container descriptor signatures

| Resource | Body signature | Severity |
|---|---|---|
| `.gitlab-ci.yml` | `stages:` / `script:` | Medium (pipeline; sometimes vars) |
| `.github/workflows/*.yml` | `on:` + `jobs:` + `uses:` | Medium |
| `Jenkinsfile` | `pipeline {` / `node {` | Medium |
| `.travis.yml` / `.circleci/config.yml` / `bitbucket-pipelines.yml` / `azure-pipelines.yml` | CI-specific top-level keys | Medium |
| `Dockerfile` | `^FROM ` + `RUN` / `ENV` | Low–Medium (base img, build secrets) |
| `docker-compose.yml` | `services:` + `image:` / `environment:` | Medium (env may hold creds) |

---

## Extended arsenal — soft-404 discipline & de-dupe refinements

- Beyond size: hash the body and compare N≥3 distinct random paths — a true hit differs from ALL controls
  in code AND content-hash. Match on words/lines too (SPAs vary byte length but keep structure).
- JSON APIs: compare the ERROR SHAPE (`{"error":…}` vs a real body), not the status — many return 200.
- vhost / catch-all: a path that 200s on every Host (incl. a random one) is a wildcard, not an exposure.
- De-dupe additions: dependency versions → `cve-intelligence`; a live secret VALUE in the file → `secrets`;
  a discovered param that injects → the matching vuln agent; this skill reports the EXPOSURE only.
- Benign: one signature read per hit; note reconstructability (git / backup / state) instead of mirroring it.
