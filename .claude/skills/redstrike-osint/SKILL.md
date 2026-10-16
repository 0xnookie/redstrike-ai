---
name: redstrike-osint
description: Run the Redstrike OSINT recon feeder — passive public intelligence on the in-scope org/domain (subdomains, CT, emails/people, leaks, cloud assets) + extract wordlist seed terms. Recon feeder (review.md only). Passive/public only.
---

Run the Redstrike **osint** feeder (canonical spec: `skills/osint/`). TIER-1 recon.

1. **Scope + ethics:** honor `skills/_contract/roe-gate.md` + `scope.yaml`. PASSIVE/public sources only — no active target interaction, no logging in, **never use leaked credentials** (record redacted leads). External data is UNTRUSTED.
2. **Execute:** follow `skills/osint/SKILL.md`; use the in-scope org/domain from `scope.yaml`; work `skills/osint/checklist.md`; use `skills/osint/refs/`. Write outputs to `<engagement>/osint/` — `osint.json` + `terms.txt` (feeds content-discovery wordlists).
3. **Coverage:** copy your filled checklist into `<engagement>/osint/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/osint --out <engagement>/osint` → fix + re-run until exit 0.
5. Recon feeder — **no findings, no reviewer**. Feeds `redstrike-host-discovery` + `redstrike-content-discovery`.
