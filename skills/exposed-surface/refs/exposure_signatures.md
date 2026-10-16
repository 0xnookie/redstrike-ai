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
nuclei -u https://HOST -t http/exposures/ -t http/misconfiguration/ -t http/exposed-panels/ -t http/backups/ -rl <rps> -jsonl -o nuclei.jsonl

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
