# Host Discovery

> TIER-1 recon feeder. Maps the external attack surface — subdomains, live hosts, ports/services,
> host-level tech. ACTIVE (DNS + probing + optional port scan) → honors `_contract/roe-gate.md`
> (scope + rate limits). Emits NO findings → `review.md` only.

## Interview
- **STEPS:** ingest scope + OSINT subdomains → active subdomain enum → resolve → probe live hosts → port/service scan (scoped) → host tech fingerprint → consolidate → review.
- **TOOLS:** `subfinder`/`amass`/`fierce`/`dnsenum`, `dnsx`, `httpx`, `naabu`/`masscan`/`rustscan`/`nmap` (scoped), `httpx -td`. Tool-first — `_contract/tooling.md`.
- **GOAL:** Produce the live-host inventory — in-scope subdomains, which are live (http/https), open ports/services, and host-level tech — so content-discovery + js-analysis know where to look. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `subdomains.txt`, `hosts.json`, `host_discovery.json`, `dangling_dns.json`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = `scope.yaml` (in-scope domains/cidrs) + `<engagement>/osint/osint.json` (passive subs). `refs/` = `host_discovery_refs.md`. Chains FROM `osint`; chains TO `content-discovery`, `js-analysis`, and the **notebook** (host/network `recon_intel`; `dangling_dns.json` → subdomain-takeover **leads** — aggregated by `scripts/notebook.py --plan`).
- **DECOMPOSITION:** n/a (recon feeder).

## Goal
Produce the in-scope live-host + service inventory. DONE = `checklist.md` `- [x]` · `review.md` PASS.

## What do we want
- In-scope subdomains (passive + active), resolved
- Which hosts are live (http/https), status, title, tech (httpx -td)
- Open ports/services (scoped, rate-limited)
- A consolidated host map to drive the rest of recon

## Steps  (action · tool · output)
1. Ingest scope + OSINT subs · `jq osint.json` + `scope.yaml` · (seed)
2. Active subdomain enum (bruteforce + permutations, in-scope only) · `subfinder`/`amass` · `subdomains.txt`
3. Resolve + dedupe (CNAME/A/NS chains) · `dnsx -a -cname -ns -resp` · `subdomains.txt` + resolved records
3b. **Dangling-DNS triage → emit `asset:dangling-dns`** · `scripts/dangling_dns.py` over the resolved
    CNAME/NS records (per-record: `{subdomain,record_type,target,target_resolves,is_wildcard}`) · `dangling_dns.json`
    — a CNAME to a known takeover-prone service (even if it resolves), a non-resolving CNAME/NS target, or a
    dangling NS is a CANDIDATE. When `emit` is true, add `asset:dangling-dns` to the recon signals the
    orchestrator feeds `coverage.py --plan` (so `subdomain-takeover` is ROUTED, not skipped) and hand the
    candidates to the `subdomain-takeover` executor as leads. No candidates ⇒ no signal (the class then
    skips with a real reason). DNS-level TRIAGE only — the executor does the HTTP-fingerprint + claimability.
4. Probe live hosts (status/title/tech) · `httpx -td -sc -title` · `hosts.json`
4b. **Reachability triage (esp. a large wildcard) — classify, then focus.** A `*.domain` wildcard can be
    hundreds–thousands of CT names of which only a handful are an internet-facing *app*. Bucket each probed
    host: **reachable** (2xx/3xx real content), **external-denied** (a gateway/WAF 403 on a host that
    resolves — reachable but policy-blocked externally), **internal-only** (DNS/connect failure — not public).
    Hunt the **reachable** set; note external-denied/internal and move on. Do NOT deep-probe all N hosts
    (slow + raises the org's WAF/IP-rep across its estate) — triage by name (auth/account/app/API/admin/
    dev-tooling/test-staging) first, then probe the shortlist low-and-slow. A direct probe is the source of
    truth for reachability (`proxy.md` §8 — a proxy can mis-report an unreachable host as live).
5. Port/service scan (scoped, rate-limited; fast sweep → service detail) · `naabu`/`masscan`/`rustscan` → `nmap -sV` · `hosts.json`
5b. **Local/container discovery** (target is localhost or a local container) — `docker ps` + `docker inspect` for bind-mounts (→ source location, enabling the white-box `source-audit`) and container-internal services (DB/cache/mail/search a host port scan can't see) · `docker` · `host_discovery.json`
6. Consolidate host map + **emit the tech signal** (`tech:wordpress`/`tech:nextjs`/`tech:shopware`, …) from the host tech fingerprint so the matching framework agent routes; flag a dev-image marker (`X-Debug-Token`/dockware/`*-dev`) for `exposed-surface` · synth · `host_discovery.json`
7. Emit summary · synth · `summary.md`
8. /REVIEW SKILL · `review.md`

## Tools
- `subfinder`, `amass`, `fierce`, `dnsenum` (subs/DNS), `dnsx` (resolve), `httpx` (probe), `naabu`/`masscan`/`rustscan` (fast port sweep) → `nmap -sV` (scoped service detail)
- **Tool-first rule + roster:** `_contract/tooling.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `scope.yaml` (in-scope domains/cidrs), `<engagement>/osint/osint.json`
- `refs/host_discovery_refs.md`

## Outputs
`subdomains.txt` · `hosts.json` · `host_discovery.json` · `summary.md` · `logs/`

## Phases
- **Phase 1 (generic):** subdomain enum + resolve + live-host probe.
- **Phase 2 (target-specific):** scoped port/service scan + host tech + consolidation.

## Safety
Only in-scope domains/CIDRs (hard stop on out-of-scope resolution). Port scanning is active — **rate-limit**,
top-ports-first, **no aggressive/`-T5` or full-range blasts** that could disrupt; honor `scope.yaml`
`no_dos`; audit-log. Out-of-scope subdomains found are reported, not probed.
