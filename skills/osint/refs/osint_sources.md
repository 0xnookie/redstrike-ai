# OSINT sources + methodology (passive, public, ethical)
# No active target interaction. Never use leaked creds — record them (redacted) as leads.

## Subdomains / DNS (passive)
- Certificate transparency: `crt.sh`, `censys`, `certspotter`.
- Passive DNS: `subfinder`, `amass enum -passive`, `assetfinder`.
- Reverse DNS / ASN: map the org's IP ranges.

## People / emails
- `theHarvester -d <domain> -b all` → emails, hosts, names.
- Derive the email/username **naming convention** (first.last / flast) → feeds auth + wordlists.
- LinkedIn/company pages for employee names (handles → wordlist terms).

## Code / secrets (public)
- GitHub/GitLab dorks: `org:<company>`, `"<domain>" password`, API keys, `.env`, internal hostnames.
- Paste sites, public S3/GCS indexes, Wayback for old endpoints.
- Breach/leak references (HaveIBeenPwned-style): RECORD exposure as a lead — **do not use** the creds.

## Cloud assets
- `cloud_enum` (buckets/apps across AWS/GCP/Azure), permutations from the org name + terms.
- Certificate SANs + CT often reveal cloud hostnames.

## Tech / exposure
- Shodan/Censys for exposed services (passive query, not scanning).
- Google dorks: `site:<domain> ext:php|aspx`, `inurl:admin`, `intitle:index.of`.

## Wordlist terms (→ terms.txt, feeds content-discovery)
Collect: product/feature names, observed URL path segments (from CT/Wayback), employee handles,
tech keywords, internal hostnames. These make a TARGET-SPECIFIC wordlist far better than a generic one.

## Ethics
Public sources only; nothing that touches the target actively; never authenticate with found creds;
stay within the authorized org; redact secrets in artifacts.

---
## Extended arsenal — certificate transparency & passive DNS (query-only, no target contact)

```
# crt.sh JSON → every logged SAN for a root domain (dedupe offline)
curl -s 'https://crt.sh/?q=%25.TARGET.com&output=json' | jq -r '.[].name_value' | sort -u
# aggregate CT + passive providers in one pass (keys in config):
subfinder -d TARGET.com -all -silent          # crt.sh/certspotter/censys/chaos/virustotal/…
amass enum -passive -d TARGET.com -silent
```
- CT extras: wildcard SANs (`*.TARGET`) reveal naming schemes; poll new log entries to catch fresh/staging hosts early.
- Passive/historical DNS (securitytrails/virustotal/otx/rapiddns/dnsdumpster-class): resolved-before A/CNAME history → retired hosts = takeover + pivot leads.

---
## Extended arsenal — org & infrastructure attribution (passive)

- Acquisitions/subsidiaries → extra root domains (corporate registries, filings) → re-feed subdomain enum.
- ASN discovery: `amass intel -org "Target Inc"` / `-asn <n>`; BGP looking-glass → ASN → announced CIDRs (scope lead only, DO NOT scan here).
- Reverse whois: registrant org/email → sibling domains (whois-history APIs).
- Tracker correlation: shared analytics / ad / tag-manager ids across sites reveal co-owned properties.
- DMARC/SPF: `_dmarc.TARGET` rua/ruf + SPF `include:` → mail vendors + more domains.

---
## Extended arsenal — search-engine & infra dork catalogue (passive)

Google:
| Goal | Query |
|---|---|
| Dir listing | `site:TARGET.com intitle:"index of"` |
| Login/admin | `site:TARGET.com inurl:(admin\|login\|portal\|signin)` |
| Docs/leaks | `site:TARGET.com ext:(pdf\|docx\|xlsx\|csv\|log\|conf\|bak\|sql)` |
| Secrets in text | `site:TARGET.com intext:(password\|api_key\|"BEGIN RSA")` |
| Errors/debug | `site:TARGET.com intext:("SQL syntax"\|"stack trace")` |
| Subdomain sweep | `site:*.TARGET.com -www` |

Shodan / Censys / FOFA (index query, zero packets to target):
| Engine | Useful filters |
|---|---|
| Shodan | `org:"Target"` · `ssl:"Target"` · `ssl.cert.subject.cn:TARGET.com` · `http.favicon.hash:<mmh3>` · `http.html:"TARGET"` · `asn:ASxxxx` |
| Censys | `services.tls.certificates.leaf_data.subject.common_name:TARGET.com` · `...subject.organization:"Target"` · `autonomous_system.asn:xxxx` |
| FOFA | `cert="TARGET.com"` · `domain="TARGET.com"` · `icon_hash="<hash>"` · `title="Target"` |

---
## Extended arsenal — GitHub / GitLab code & secret dorking (public)

```
# Secret scanners over a cloned/downloaded PUBLIC repo (no auth, no target contact):
trufflehog github --org=TARGET          # or: trufflehog filesystem ./repo
gitleaks detect --source ./repo --no-git
```
| Target | Dork (web/API) |
|---|---|
| Org code | `org:TARGET` · GitLab group search |
| Domain refs | `"TARGET.com"` · `"internal.TARGET"` |
| Secrets | `"TARGET" password` · `filename:.env TARGET` · `filename:.npmrc _auth` |
| Cloud creds | `"AKIA" TARGET` · `filename:credentials aws` · `filename:config gcloud` |

Committer emails in public commits → employee naming convention; ex-employee forks/gists leak old config.

---
## Extended arsenal — people / email harvesting & permutation (passive)

```
theHarvester -d TARGET.com -b all -f harvest        # emails/hosts/names across sources
```
- Name→email permutation: `{first}.{last}` `{f}{last}` `{first}{l}` `{last}{f}`@domain → candidate list (infer pattern from MX/catch-all policy, do NOT send mail).
- Enrichment (hunter.io / snov.io-class): pattern + confidence, no mail sent.
- Handles/usernames → pivot across code hosts + social → more identifiers → `terms.txt`.

---
## Extended arsenal — breach / leak corpora (reference as CATEGORIES only)

- Breach-notification services (hibp-class) → *which* accounts/domains appear in a breach.
- Leak-aggregator corpora (dehashed-class) + public combolists → exposed credential existence.
- RECORD exposure as a redacted lead (account + corpus name); **never** authenticate with any recovered credential.

---
## Extended arsenal — document & metadata OSINT (passive)

```
# Harvest public docs, then strip metadata (authors, software, internal paths, usernames):
metagoofil -d TARGET.com -t pdf,doc,docx,xls,xlsx,ppt -o docs -l 100
exiftool -r -Author -Creator -Producer -Software -'*GPS*' docs/
```
- Office/PDF metadata → employee/AD usernames, internal UNC paths (`\\server\share`), software versions (→ CVE leads).
- EXIF geotags on public images → site locations. Feed names/usernames/paths into `terms.txt`.

---
## Extended arsenal — passive wordlist seed extraction (→ terms.txt)

```
# Tokenize passively-collected SANs/URLs into terms (no requests to the target):
cat ct_sans.txt wayback_urls.txt | grep -oE '[a-zA-Z0-9_-]{3,}' | tr 'A-Z' 'a-z' | sort -u > terms.txt
```
- Seeds: CT SAN labels, historical path segments, repo/branch names, doc-metadata terms, product/feature names, employee handles, ASN org tokens.
- Keep env/role suffixes seen in history (`-staging`,`-dev`,`-api`,`v1`,`uat`) → permutation seeds for host-discovery.
