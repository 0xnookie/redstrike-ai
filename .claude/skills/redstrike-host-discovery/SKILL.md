---
name: redstrike-host-discovery
description: Run the Redstrike host-discovery recon feeder — in-scope subdomains, live hosts, ports/services, host tech — into host_discovery.json for content-discovery + the vuln agents. Recon feeder (review.md only). Scope-gated, rate-limited.
---

Run the Redstrike **host-discovery** feeder (canonical spec: `skills/host-discovery/`). TIER-1 recon.

1. **Scope:** honor `skills/_contract/roe-gate.md` + `scope.yaml`. In-scope domains/CIDRs ONLY (hard stop on out-of-scope). Port scanning is active — **rate-limit**, top-ports-first, no aggressive/full-range blasts; honor `no_dos`.
2. **Execute:** follow `skills/host-discovery/SKILL.md`; consume `scope.yaml` + `<engagement>/osint/osint.json`; work `skills/host-discovery/checklist.md`; use `skills/host-discovery/refs/`. Write outputs to `<engagement>/host-discovery/` — `host_discovery.json` (live hosts + services + tech).
3. **Coverage:** copy your filled checklist into `<engagement>/host-discovery/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/host-discovery --out <engagement>/host-discovery` → fix + re-run until exit 0.
5. Recon feeder — **no findings, no reviewer**. Feeds `redstrike-content-discovery` + `redstrike-js-analysis`.
