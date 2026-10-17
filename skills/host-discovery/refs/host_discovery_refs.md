# Host discovery tooling + method
# In-scope only. Active probing is rate-limited and non-disruptive.

## Subdomain enumeration
- Passive (from osint): `subfinder`, `amass enum -passive`, CT.
- Active (in-scope): `amass enum -active`, bruteforce (`puredns` + a resolvers list + a subdomain wordlist),
  permutations (`gotator`/`altdns` from osint terms).

## Resolve + probe
- `dnsx -resp -a -cname` to resolve + dedupe; drop out-of-scope.
- `httpx -td -title -sc -ip -cdn` → live hosts, status, title, tech, behind-CDN flag.

## Ports / services (scoped)
- `naabu -top-ports 100` first (fast, rate-limited), then `nmap -sV` on the open ports for service/version.
- Respect `scope.yaml` cidrs + `rate_limit_rps`; **never** full-range `-p-` blasts or `-T5` on prod.
- Behind a CDN/WAF → note it (scanning the CDN edge, not origin); don't hammer.

## Consolidate (host_discovery.json shape)
`{ hosts: [ {host, ip, live, ports:[{port,service,version}], tech:[...], title, cdn} ], out_of_scope:[...] }`
Feeds `content-discovery` (per live host) + `js-analysis`.

---
## Extended arsenal — subdomain enumeration (passive→active, scope-gated)

```
subfinder -d TARGET.com -all -silent -o passive.txt          # passive multi-source (keys in config)
assetfinder --subs-only TARGET.com >> passive.txt
amass enum -active -d TARGET.com -brute -o active.txt         # active enum + brute (in-scope only)
puredns bruteforce subs-wordlist.txt TARGET.com -r resolvers.txt -w brute.txt   # DNS brute via massdns
sort -u passive.txt active.txt brute.txt > subdomains.txt
```
- Keep passive (no target DNS) vs active (resolve/brute) separated in logs.
- `resolvers.txt` = validated trusted resolvers (refresh often) → avoids false positives / wildcard poisoning.

---
## Extended arsenal — permutation + mass resolution

```
gotator -sub subdomains.txt -perm terms.txt -depth 1 -numbers 3 > perms.txt
altdns -i subdomains.txt -o perms2.txt -w terms.txt ; ripgen -d subdomains.txt >> perms.txt
shuffledns -d TARGET.com -list perms.txt -r resolvers.txt -o perm-resolved.txt   # massdns-backed
puredns resolve perms.txt -r resolvers.txt --wildcard-tests 30 -w resolved.txt    # wildcard-safe
```
- Always wildcard-filter (`*.TARGET` catch-all) before trusting resolved perms.
- massdns is the engine under shuffledns/puredns — tune concurrency (`-s`) to the rate budget.

---
## Extended arsenal — ASN → CIDR expansion (scope-gated)

```
asnmap -d TARGET.com -silent          # domain → ASN → announced CIDRs
asnmap -a AS12345 -silent             # ASN → prefixes
amass intel -org "Target Inc"         # org name → ASNs
```
- Expand only CIDRs confirmed in `scope.yaml`; out-of-scope ranges are reported, never scanned.
- Reverse-DNS the in-scope ranges (`dnsx -ptr -l cidr-hosts.txt`) for more names; feed to the scan tiers.

---
## Extended arsenal — favicon-hash & TLS-SAN pivots

```
httpx -u https://HOST -favicon            # prints the mmh3 favicon hash
#   pivot the hash in Shodan (http.favicon.hash:) / FOFA (icon_hash=) → sibling hosts (query, don't scan).
httpx -l hosts.txt -tls-grab -json | jq -r '.tls.subject_an[]?' | sort -u   # cert SAN names not in DNS
```
New in-scope names found → re-feed the subdomain list.

---
## Extended arsenal — port/service scan tiers (rate-limited, non-disruptive)

```
# T1 triage — top ports, capped rate:
naabu -list hosts.txt -top-ports 100 -rate <pps> -o open-top.txt
# T2 breadth (if authorized) — full TCP, bounded:
naabu -list hosts.txt -p - -rate <pps> -o open-full.txt        # or: masscan --rate <pps> -p1-65535
# T3 depth — service/version on CONFIRMED-open ports only:
nmap -sV -sC -Pn -n -p <open-csv> -iL hosts.txt -oA nmap_svc   # no -T5, no blind -p-
# UDP (selective, slow) — named services only:
nmap -sU -sV --top-ports 20 -Pn -n -iL hosts.txt -oA nmap_udp
```
- Honor `rate_limit_rps` / `no_dos`; never run depth before triage; masscan for breadth, nmap for accuracy.
- Behind CDN/WAF → you scan the edge not origin — note it, don't hammer.

---
## Extended arsenal — tech / service fingerprinting

```
httpx -l live.txt -td -title -sc -server -cdn -tls-grab -json -o httpx.json   # tech/title/status/CDN/cert
whatweb -a 3 https://HOST                                   # plugin-based stack fingerprint
```
- Record per host: server, framework, language, CMS + version, WAF/CDN, cert SANs.
- Version strings feed `cve-intelligence`; no exploitation here (recon feeder).
