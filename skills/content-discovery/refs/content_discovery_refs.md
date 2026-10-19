# Content discovery + custom wordlist building
# In-scope, rate-limited. Prefer a smart TARGET-SPECIFIC wordlist over mega-lists on prod.

## Crawl
- `katana -jc -jsl -d 3` (JS-aware), `hakrawler`, `gospider`. Authed crawl with `auth.env` cookies.
- Historical: `gau`, `waymore`, `github-endpoints`. Merge + dedupe + de-scope.

## Building the custom wordlist (the point)
A target-specific list finds what generic lists miss. Combine:
1. **OSINT terms** (`osint/terms.txt`) — product/feature names, employee handles, internal hostnames.
2. **Crawled path segments** — split crawled URLs into path tokens (`/admin/users/export` → admin, users, export).
3. **JS strings** — identifiers, routes, API paths from `js-analysis/out/<site>/beautified/` + `findings/endpoints.jsonl`.
4. **A base list** — `seclists` (raft/dirb) as the backbone.
5. **Mutations** — add extensions seen on the target (`.php`,`.json`,`.bak`), case variants.
```
cat osint/terms.txt crawl_tokens.txt js_tokens.txt base.txt | sort -u > custom_wordlist.txt
# cewl the site for more terms:  cewl -d 2 -m 5 https://TARGET -w cewl.txt
```

## Brute-force
- `ffuf -w custom_wordlist.txt -u https://HOST/FUZZ -mc 200,204,301,302,307,401,403 -rate <scope rps>`
- `feroxbuster -u https://HOST -w custom_wordlist.txt --rate-limit <rps>` (recursive, careful).
- `gobuster dir -u https://HOST -w custom_wordlist.txt -b 404,403 -q` · `dirsearch -u https://HOST -w custom_wordlist.txt` (alternatives — same job, pick per host).
- Extensions: `-e .php,.json,.bak,.old,.zip,.config`. Filter noise (size/word count). Tool-first: never hand-roll a brute-forcer (`_contract/tooling.md`).

## Parameters
- `arjun -u https://HOST/endpoint`, `paramspider -d HOST`, `x8` — active param mining.
- From crawl: extract query keys + body fields + JS-referenced params.

## Outputs feed
`endpoints.txt` + `params.txt` + `custom_wordlist.txt` feed `js-analysis` and every `<class>-context`
feeder (which consume params/endpoints). The custom wordlist is reusable across fuzzing steps.

---
## Extended arsenal — wordlist catalogue (pick per phase; scope-gated, rate-limited)

| Category | Representative list (seclists) | Use when |
|---|---|---|
| Quick dirs | `Discovery/Web-Content/raft-small-directories.txt` | first fast sweep |
| Full dirs | `raft-large-directories.txt` / `directory-list-2.3-medium.txt` | deeper dir brute |
| Files | `raft-large-files.txt` (+ `-e` exts) | file-name brute |
| API routes | `api/api-endpoints.txt` | REST/JSON apps |
| High-signal | `quickhits.txt` / `RobotsDisallowed/top10000.txt` | one-shot, low-noise |
| Backups | `Discovery/Web-Content/BackupFiles.txt` | backup/temp hunt |
| Params | `burp-parameter-names.txt` / curated param megalists | param mining |
| Tech-specific | `CMS/*`, `Programming-Language-Specific/*` | after tech fingerprint |

Prefer `custom_wordlist.txt` first; escalate to large lists only inside the rate budget.

---
## Extended arsenal — fuzzer flag recipes (scope-gated, rate-limited)

```
# ffuf — calibrated auto-filter + rate cap + recursion + extensions + JSON out
ffuf -w custom_wordlist.txt:FUZZ -u https://HOST/FUZZ \
  -mc 200,204,301,302,307,401,403,405 -ac -recursion -recursion-depth 2 \
  -e .php,.json,.bak,.old,.zip,.config -t 20 -rate <rps> -timeout 10 -o ffuf.json -of json
#   -ac auto-calibrates soft-404; add -fs/-fw/-fl to drop a fixed noise size/word/line count.
```
```
feroxbuster -u https://HOST -w custom_wordlist.txt -x php,json,bak -d 2 \
  --rate-limit <rps> --scan-limit 2 -C 404,403 --filter-size <n> -o ferox.txt
gobuster dir -u https://HOST -w custom_wordlist.txt -x php,json,bak -b 404,403 -t 20 -q -o gob.txt
dirsearch -u https://HOST -w custom_wordlist.txt -e php,json,bak -r -R 2 -t 20 --exclude-status 404,403
```

---
## Extended arsenal — recursion & extension strategy

- Every newly found directory is a new brute root — recurse (bounded depth) or re-queue it.
- Tie extensions to the fingerprinted stack (`.php`/`.phtml`, `.aspx`/`.asmx`, `.jsp`, `.json`/`.yaml`); don't fuzz all exts on every host (wastes rate budget).
- Two-pass: small list wide (all hosts) → large list deep (only hosts/dirs that looked alive).
- Always calibrate soft-404 (random-path baseline) before trusting any 200.

---
## Extended arsenal — backup / temp / source-leak patterns

For each discovered `file.ext`, also request on-host:
```
file.ext~   #file.ext#   .file.ext.swp   file.ext.bak  file.ext.old  file.ext.save
file.ext.1  file.ext.orig  file.ext.tmp  file.ext.copy  file.ext.txt  file.zip  file.tar.gz
```
High-signal exposures: `/.git/HEAD` (+ dumpable `.git/`), `/.svn/`, `/.env`, `/.DS_Store`, `/backup.sql`, `/db.sql.gz`, `/wp-config.php.bak`, `/web.config.bak`, source maps `*.js.map`, `/.well-known/`.
```
ffuf -w BackupFiles.txt:FUZZ -u https://HOST/FUZZ -mc 200 -ac   # dedicated backup sweep
```
Confirming the exposure is here; validating any secret found inside defers to the secrets agent.

---
## Extended arsenal — virtual-host & vhost fuzzing

```
# same IP, different Host → hidden apps DNS doesn't reveal
ffuf -w vhosts.txt:FUZZ -u https://HOST/ -H "Host: FUZZ.TARGET.com" -mc all -ac -t 20 -rate <rps>
#   -fs <default-vhost-size> drops the default-vhost baseline.
gobuster vhost -u https://HOST -w vhosts.txt --append-domain -o vhost.txt
```
Seed `vhosts.txt` from osint `terms.txt` + enumerated subdomains. Storage-bucket guessing stays in cloud/osint scope.

---
## Extended arsenal — historical URL & archive mining

```
gau --subs TARGET.com | anew crawl.txt                 # wayback/otx/commoncrawl union
waybackurls TARGET.com | anew crawl.txt
katana -u https://HOST -jc -jsl -kf all -d 3 -aff      # active crawl incl. JS + known-files
gospider -s https://HOST -d 3 --sitemap --robots -a    # crawl + archive sources
```
- Dedupe + de-scope (`sort -u`, drop out-of-scope hosts, strip `\.(png|jpg|css|woff2?)`).
- Extract params: `grep -oE '[?&][a-zA-Z0-9_]+=' | sort -u` → seeds `params.txt`; path tokens → `custom_wordlist.txt`.

---
## Extended arsenal — parameter discovery (expanded)

```
arjun -u https://HOST/endpoint -m GET,POST -oT params.txt     # infers hidden params by diff
arjun -i endpoints.txt -oT params.txt                         # batch over discovered endpoints
x8 -u https://HOST/endpoint -w param-names.txt -X GET POST    # high-signal diffing miner
paramspider -d TARGET.com                                     # params from archived URLs (passive)
```
- Mine from three sources: active (arjun/x8), archived (paramspider/gau), code (JS vars/routes from js-analysis).
- Rate-limit active miners the same as brute-force; discovery only — behavior testing hands to the vuln agents.
