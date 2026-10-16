# Content discovery + custom wordlist building
# In-scope, rate-limited. Prefer a smart TARGET-SPECIFIC wordlist over mega-lists on prod.

## Crawl
- `katana -jc -jsl -d 3` (JS-aware), `hakrawler`, `gospider`. Authed crawl with `auth.env` cookies.
- Historical: `gau`, `waymore`, `github-endpoints`. Merge + dedupe + de-scope.

## Building the custom wordlist (the point)
A target-specific list finds what generic lists miss. Combine:
1. **OSINT terms** (`osint/terms.txt`) — product/feature names, employee handles, internal hostnames.
2. **Crawled path segments** — split crawled URLs into path tokens (`/admin/users/export` → admin, users, export).
3. **JS strings** — identifiers, routes, API paths from `js-analysis/js/beautified/` + `endpoints_*.txt`.
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
