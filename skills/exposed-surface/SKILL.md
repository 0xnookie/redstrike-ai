# Exposed Surface Agent

> ATOMIC single agent (no feeder) — one confirmation: an unauthenticated request reaches a **sensitive,
> unintended** file / directory / panel, proven by a response-body **signature** (not a bare status code).
> This is the active **fuzzing** agent — it turns content-discovery's dir/file/param brute-force into
> signature-confirmed findings.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` (GET/HEAD-only, rate-limited, no mass
> exfiltration). Carries `review.md` + `verify.md`. **Tool-first** — see `_contract/tooling.md` (never
> hand-roll a fuzzer/crawler when `ffuf`/`feroxbuster`/`gobuster`/`nuclei`/`katana` exists).

## Interview
- **STEPS:** ingest recon surface + scope → fingerprint tech/WAF → sensitive file/dir fuzz → templated exposure scan → parameter fuzz/discovery → benign signature-confirm each hit → de-dupe + classify + rate → emit → review → verify.
- **TOOLS:** `ffuf`/`feroxbuster`/`gobuster`/`dirsearch` (dir/file fuzz), `nuclei` (`http/exposures`,`http/misconfiguration`,`http/exposed-panels`,`http/backups`), `wafw00f`+`httpx -td` (fingerprint), `arjun`/`paramspider`/`x8` (params), `katana` (fallback crawl), `git-dumper` (VCS reconstructability — benign), `jq`/`curl`. See §Tools + `_contract/tooling.md`.
- **GOAL:** Confirm unauthenticated exposure of sensitive content — VCS (`/.git`), backups, `.env`/config, data dumps, directory listings, debug/actuator panels, nuclei-class info leaks — each proven by a response-body signature, de-duped against `secrets`/`security-headers`/`privesc`, benign. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `targets.txt`, `fingerprint.json`, `fuzz_raw.jsonl`, `nuclei.jsonl`, `params_found.txt`, `confirmed.jsonl`, `findings.json`, `evidence/`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = `content-discovery/{endpoints.txt,params.txt,custom_wordlist.txt,crawl.txt}` + `host-discovery/host_discovery.json` + `js-analysis/endpoints_*.txt`/`routes.md` + `scope.yaml`. `refs/` = `sensitive_paths.txt` (fuzz wordlist) + `exposure_signatures.md` (confirmation signatures + severity + de-dup routing). Chains FROM `content-discovery`, `host-discovery`, `js-analysis`; chains TO `secrets` (secret validation), `reporting`.
- **DECOMPOSITION:** n/a (atomic).

## Goal
Confirm sensitive, unintended exposures on in-scope hosts with a benign content-signature proof, and emit
`findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` all `- [x]` · `review.md` PASS · every finding accepted.

## What do we want
- VCS exposure (`/.git/`, `/.svn/`, `/.hg/`) — walkable / source-reconstructable
- Backups + dumps (`.bak`/`.old`/`~`/`.swp`/`.zip`/`.tar.gz`/`.sql`) and editor/swap leftovers
- `.env` / config / secrets files, cloud + CI config, `.DS_Store`
- Directory listing ("Index of /") exposing a sensitive tree
- Debug / admin / monitoring panels + framework actuators (`/actuator`, `/server-status`, `phpinfo`, `/metrics`, swagger/openapi)
- Hidden / undocumented parameters (surface only → handed to the vuln agents)

## Steps  (action · tool · output)
1. Ingest recon surface + de-scope to in-scope hosts · `jq`/`rg` over content-discovery + host-discovery + js-analysis · `targets.txt`
2. Fingerprint tech + WAF (tune lists, pace, avoid blocks) · `wafw00f` + `httpx -td -sc` · `fingerprint.json`
3. Sensitive file/dir fuzz (`refs/sensitive_paths.txt` + `custom_wordlist.txt`, rate-limited, soft-404 filtered) · `ffuf`/`feroxbuster`/`gobuster`/`dirsearch` · `fuzz_raw.jsonl`
4. Templated exposure scan (info leak / misconfig / exposed panels / backups) · `nuclei -t http/exposures -t http/misconfiguration -t http/exposed-panels -t http/backups` · `nuclei.jsonl`
5. Parameter fuzz/discovery (confirm hidden params; hand injection to the vuln agents) · `arjun`/`paramspider`/`x8` · `params_found.txt`
6. Benign signature-confirm each candidate (body matches `refs/exposure_signatures.md`; soft-404/wildcard ruled out) · `curl` + match · `confirmed.jsonl` + `evidence/<id>/`
7. De-dupe (vs `secrets`/`security-headers`/`privesc`) + classify (OWASP/CWE) + rate (CVSS) + write finding · synth · `findings.json`
8. Emit report · synth · `report.md`
9. /REVIEW SKILL · `review.md` · 10. /VERIFY · `verify.md`

## Tools
- **Dir/file fuzz:** `ffuf` (`-w <wordlist>:FUZZ -u https://HOST/FUZZ -mc all -ac`), `feroxbuster` (recursive, `--rate-limit`), `gobuster dir`, `dirsearch`, `dirb` (legacy). Prefer `content-discovery/custom_wordlist.txt` + `refs/sensitive_paths.txt`.
- **Templated exposures:** `nuclei -t http/exposures/ -t http/misconfiguration/ -t http/exposed-panels/ -t http/backups/` (rate-limited).
- **Fingerprint:** `wafw00f`, `httpx -td -sc -title`.
- **Params:** `arjun`, `paramspider`, `x8`.
- **VCS / confirm:** `git-dumper` (reconstructability check — benign, do NOT bulk-dump a live repo), `curl`, `jq`.
- **Crawl fallback** (if content-discovery wasn't run): `katana -jc`.
- **Tool-first rule + roster:** `_contract/tooling.md`. **Fetch ladder:** `_contract/anti-automation-ladder.md`.

## Inputs
- `content-discovery/{endpoints.txt,params.txt,custom_wordlist.txt,crawl.txt}`, `host-discovery/host_discovery.json`, `js-analysis/endpoints_*.txt`/`routes.md`
- `scope.yaml`, `refs/sensitive_paths.txt`, `refs/exposure_signatures.md`

## Outputs
`targets.txt` · `fingerprint.json` · `fuzz_raw.jsonl` · `nuclei.jsonl` · `params_found.txt` · `confirmed.jsonl` · `findings.json` · `evidence/` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** ingest + fingerprint + fuzz + templated scan (map candidate exposures).
- **Phase 2 (target-specific):** signature-confirm + de-dupe + classify + rate + report.

## Safety
ACTIVE → `_contract/roe-gate.md`. **GET/HEAD only**, benign — never write/delete, never brute-force auth,
never DoS. **Rate-limit** to `scope.yaml` `rate_limit_rps`; in-scope hosts only; filter soft-404s
(wildcard/catch-all) before claiming a hit. **No mass exfiltration** — prove exposure with a single
signature read (one `/.git/HEAD`, one `.env` line); note reconstructability instead of mirroring the whole
repo/DB/heapdump. **Redact** any secret to a fingerprint in evidence and hand live-secret validation to
`secrets`. Prefer the custom/sensitive wordlists (fewer, smarter requests) over mega-lists on prod.
Audit-log.
