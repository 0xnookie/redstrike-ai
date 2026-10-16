---
name: redstrike-content-discovery
description: Run the Redstrike content-discovery recon feeder — crawl + historical URLs + build a TARGET-SPECIFIC custom wordlist (from OSINT + crawl + JS) + directory/file brute-force + parameter discovery. Recon feeder (review.md only). Scope-gated, rate-limited.
---

Run the Redstrike **content-discovery** feeder (canonical spec: `skills/content-discovery/`). TIER-1 recon.

1. **Scope:** honor `skills/_contract/roe-gate.md` + `scope.yaml`. Active crawl + brute-force — **rate-limit** (respect `rate_limit_rps`); in-scope hosts only; prefer the custom wordlist (fewer, smarter requests) over mega-lists on prod; honor `no_dos`.
2. **Execute:** follow `skills/content-discovery/SKILL.md`; consume `<engagement>/host-discovery/host_discovery.json` (live hosts) + `<engagement>/osint/terms.txt`; work `skills/content-discovery/checklist.md`; use `skills/content-discovery/refs/`. Write outputs to `<engagement>/content-discovery/` — `endpoints.txt` + `params.txt` + **`custom_wordlist.txt`** + `content.json`.
3. **Coverage:** copy your filled checklist into `<engagement>/content-discovery/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/content-discovery --out <engagement>/content-discovery` → fix + re-run until exit 0.
5. Recon feeder — **no findings, no reviewer**. Feeds `redstrike-js-analysis` + every `<class>-context` feeder (endpoints/params/wordlist).
