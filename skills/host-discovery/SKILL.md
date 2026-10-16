# Host Discovery

> TIER-1 recon feeder. Maps the external attack surface — subdomains, live hosts, ports/services,
> host-level tech. ACTIVE (DNS + probing + optional port scan) → honors `_contract/roe-gate.md`
> (scope + rate limits). Emits NO findings → `review.md` only.

## Interview
- **STEPS:** ingest scope + OSINT subdomains → active subdomain enum → resolve → probe live hosts → port/service scan (scoped) → host tech fingerprint → consolidate → review.
- **TOOLS:** `subfinder`/`amass`/`fierce`/`dnsenum`, `dnsx`, `httpx`, `naabu`/`masscan`/`rustscan`/`nmap` (scoped), `httpx -td`. Tool-first — `_contract/tooling.md`.
- **GOAL:** Produce the live-host inventory — in-scope subdomains, which are live (http/https), open ports/services, and host-level tech — so content-discovery + js-analysis know where to look. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `subdomains.txt`, `hosts.json`, `host_discovery.json`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = `scope.yaml` (in-scope domains/cidrs) + `<engagement>/osint/osint.json` (passive subs). `refs/` = `host_discovery_refs.md`. Chains FROM `osint`; chains TO `content-discovery`, `js-analysis`.
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
3. Resolve + dedupe · `dnsx` · `subdomains.txt`
4. Probe live hosts (status/title/tech) · `httpx -td -sc -title` · `hosts.json`
5. Port/service scan (scoped, rate-limited; fast sweep → service detail) · `naabu`/`masscan`/`rustscan` → `nmap -sV` · `hosts.json`
6. Consolidate host map · synth · `host_discovery.json`
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
