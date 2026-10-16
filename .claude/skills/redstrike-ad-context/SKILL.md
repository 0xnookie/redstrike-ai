---
name: redstrike-ad-context
description: Run the Redstrike Active Directory context feeder — enumerate the domain (users/groups/computers/GPOs/trusts), collect BloodHound, flag roastable/delegation/high-priv principals + ACL edges + ADCS templates + attack paths into ad_context.json. Internal/assumed-breach recon feeder (review.md only). Requires an authorized foothold.
---

Run the Redstrike **ad-context** feeder (canonical spec: `skills/ad-context/`). TIER-2 (Active Directory, internal).

1. **Scope + foothold:** honor `skills/_contract/roe-gate.md` + `scope.yaml`. INTERNAL / assumed-breach — requires an **authorized foothold** (domain creds / shell) in scope; do not proceed without one. Enumeration only (exploitation = variants). Collection can be noisy — respect any stealth RoE.
2. **Execute:** follow `skills/ad-context/SKILL.md`; use the foothold from `scope.yaml`; work `skills/ad-context/checklist.md`; use `skills/ad-context/refs/ad_methodology.md`. Write outputs to `<engagement>/ad-context/` — key artifact `ad_context.json` (validate against `skills/_contract/ad_context.schema.json`) + BloodHound data.
3. **Coverage:** copy your filled checklist into `<engagement>/ad-context/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/ad-context --out <engagement>/ad-context` → fix + re-run until exit 0.
5. Recon feeder — **no findings, no reviewer**. `ad_context.json` feeds `redstrike-ad-kerberos | ad-acl-abuse | ad-adcs | ad-lateral-movement`.
