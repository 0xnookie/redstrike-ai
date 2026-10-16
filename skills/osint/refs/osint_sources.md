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
