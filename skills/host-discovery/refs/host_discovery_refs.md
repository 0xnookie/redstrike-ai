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
