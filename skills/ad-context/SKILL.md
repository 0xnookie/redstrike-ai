# AD Context (shared feeder)

> RECON / context feeder for the Active Directory family (variants: `ad-kerberos`, `ad-acl-abuse`,
> `ad-adcs`, `ad-lateral-movement`). INTERNAL / assumed-breach — starts from authorized domain creds or a
> foothold. ACTIVE (LDAP + collection) → imports `_contract/roe-gate.md`. Emits NO findings → `review.md` only.
> Output: `ad_context.json` (schema `_contract/ad_context.schema.json`).

## Interview
- **STEPS:** confirm foothold → enumerate domain (users/groups/computers/GPOs/trusts) → collect BloodHound data → flag roastable/delegation/high-priv principals → map interesting ACL edges → enumerate ADCS templates → compute attack paths → emit → review.
- **TOOLS:** `bloodhound-python`/`SharpHound`, `ldapdomaindump`, `netexec`(cme), `certipy find`, BloodHound analysis.
- **GOAL:** Map the domain into `ad_context.json` — principals + flags, ACL edges, ADCS templates, and attack paths from the foothold to high-value targets — so the variants exploit specific vectors. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `domain.json`, `bloodhound/`, `ad_context.json`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = `scope.yaml` (in-scope domain/hosts + the authorized foothold creds) + `oob.collaborator`. `refs/` = `ad_methodology.md`. Chains TO all four AD variants.
- **DECOMPOSITION:** n/a (feeder).

## Goal
Produce the shared AD attack map. DONE = `checklist.md` `- [x]` · `review.md` PASS (`ad_context.json` validates).

## What do we want
- Domain + DC + functional level; our foothold (identity + privs)
- Principals flagged: kerberoastable, AS-REP-roastable, delegation (unconstrained/constrained/RBCD), high-priv, adminCount
- Interesting ACL edges (GenericAll/WriteDacl/AddKeyCredentialLink/DCSync/…)
- ADCS CA + vulnerable templates (ESC1-8)
- Attack paths (foothold → DA / high-value) from BloodHound

## Steps  (action · tool · output)
1. Confirm the authorized foothold (creds/shell) from `scope.yaml` · read · (into context)
2. Enumerate domain (users/groups/computers/GPOs/trusts) · `netexec` + `ldapdomaindump` · `domain.json`
3. Collect BloodHound data · `bloodhound-python`/`SharpHound` · `bloodhound/`
4. Flag roastable / delegation / high-priv principals · BloodHound + `netexec` · `ad_context.json`
5. Map interesting ACL edges · BloodHound · `ad_context.json`
6. Enumerate ADCS templates (ESC) · `certipy find` · `ad_context.json`
7. Compute attack paths (foothold → DA/high-value) · BloodHound · `ad_context.json`
8. Consolidate + validate vs schema · synth · `ad_context.json`
9. Emit summary · synth · `summary.md` · 10. /REVIEW · `review.md`

## Tools
- `bloodhound-python`/`SharpHound`, `ldapdomaindump`, `netexec` (crackmapexec), `certipy find`, BloodHound GUI
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `scope.yaml` (in-scope domain/hosts + authorized foothold creds), `oob.collaborator`
- `refs/ad_methodology.md`

## Outputs
`domain.json` · `bloodhound/` · `ad_context.json` · `summary.md` · `logs/`

## Phases
- **Phase 1 (generic):** domain enumeration + BloodHound collection.
- **Phase 2 (target-specific):** flag principals + ACL/ADCS + attack-path computation.

## Safety
Internal / assumed-breach — requires an **authorized foothold** (do not proceed without one in scope).
Enumeration only here (no exploitation — variants, approval-gated). Collection can be noisy — respect any
RoE on stealth; don't trip production AD defenses recklessly. Scope to the authorized domain; audit-log.
