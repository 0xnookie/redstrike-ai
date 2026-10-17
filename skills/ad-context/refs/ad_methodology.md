# Active Directory methodology (shared by the AD variants)
# Internal / assumed-breach. Authorized foothold REQUIRED. High-impact — exploitation is approval-gated.
# This file = the method/phase map. For EXACT invocations per variant (enum/kerberos/acl/adcs/lateral),
# incl. the novel techniques (SOAPHound, TimeRoasting, Sapphire tickets, ESC9-15, certsync/masky, RBCD
# without DA, coercion triggers, remote-exec matrix), see refs/ad_commands.md.

## Enumeration (feeder)
- `netexec smb <range> -u u -p p` (hosts, shares, signing, null sessions), `--users`, `--groups`, `--pass-pol`.
- `ldapdomaindump` / `ldapsearch` for a full domain dump.
- **BloodHound:** `bloodhound-python -d <domain> -u u -p p -c All` (or SharpHound) → ingest → analyze paths.
- `certipy find -u u -p p -dc-ip <dc>` → ADCS templates + ESC flags.

## Kerberos (→ ad-kerberos)
- **Kerberoasting:** `GetUserSPNs.py`/`netexec --kerberoasting` → TGS hashes → crack OFFLINE (`hashcat -m 13100`).
- **AS-REP roasting:** accounts with `DONT_REQ_PREAUTH` → `GetNPUsers.py` → `hashcat -m 18200`.
- **Delegation:** unconstrained (capture TGT via coercion), constrained (S4U2Self/Proxy), RBCD
  (write `msDS-AllowedToActOnBehalfOfOtherIdentity` → S4U).
- **Tickets:** golden (krbtgt), silver (service) — forge; HIGH RISK, approval, demonstrate capability only.

## ACL abuse (→ ad-acl-abuse)
- Edges: `GenericAll`/`GenericWrite`/`WriteDacl`/`WriteOwner`/`ForceChangePassword`/`AddMember`.
- **Shadow credentials:** `AddKeyCredentialLink` → `pywhisker`/`certipy shadow` → PKINIT → NT hash.
- **DCSync:** `WriteDacl` on domain → grant replication → `secretsdump.py` (HIGH RISK, approval, one test account).

## ADCS (→ ad-adcs)
- ESC1 (SAN), ESC2 (any-purpose), ESC3 (enrollment agent), ESC4 (template ACL), ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2),
  ESC7 (CA ACL), ESC8 (NTLM relay to web enrollment). `certipy req`/`certipy relay`.

## Lateral movement (→ ad-lateral-movement)
- PtH (`netexec smb -H <hash>`), PtT (export/import ticket), overpass-the-hash.
- Exec: `psexec`/`smbexec`/`wmiexec`/`evil-winrm`.
- **NTLM relay:** `ntlmrelayx` + coercion (`PetitPotam`/`Coercer`) — approval.

## Safety
Authorized foothold + scope. Crack hashes OFFLINE. Demonstrate the VECTOR (capability), don't fully
compromise the domain: no real golden ticket persistence, no full `secretsdump` of the domain, no
disruptive coercion on prod. Clean up created objects (shadow creds, RBCD, added members). Approval-gated.

---

## Extended arsenal — Attack-path methodology (assumed-breach → domain dominance → trusts)
Flow only; exact invocations per phase live in `refs/ad_commands.md`. Every WRITE is on a TEST principal with a
pre-recorded original + a cleanup-ledger entry; high-impact steps are APPROVAL-GATED; secrets are redacted to
fingerprints; hashes crack OFFLINE; the goal is to prove the VECTOR, never to take and hold the domain.

**0 · Assumed-breach baseline.** Confirm the authorized foothold (identity + privileges) and the RoE / stealth
constraints. Define the test principals, the benign markers, and the cleanup ledger BEFORE the first write.

**1 · Enumerate (feeder → ad-context).** Collect BloodHound (All; SOAPHound/ADWS when stealth matters), sweep
with NetExec, `certipy find` for ESC flags, dump trusts/GPOs. Mark roastable / delegation / high-priv principals,
ACL edges, and writable templates. Compute shortest paths from the foothold to Tier-0 → `ad_context.json`.

**2 · Credential access.** Lowest-noise first: AS-REP / Kerberoast (crack OFFLINE), coercion → NetNTLMv2 (OFFLINE),
LAPS / gMSA read where entitled, secrets in object descriptions / SYSVOL-NETLOGON. Redact every recovery to a fp.

**3 · Escalate (local + domain).** Walk the BloodHound edge: pick the QUIETEST reversible primitive (shadow-cred
over a password reset; an ACL grant you remove; an ADCS cert you revoke). Each exercised on a TEST principal, reverted.

**4 · Lateral movement.** Turn a recovered credential into reach: PtH / PtT / overpass-the-hash to ONE more
in-scope host, pick the exec channel by noise, prove reach with a benign command, then purge tickets.

**5 · Domain dominance (CAPABILITY-ONLY, APPROVAL-GATED).** Single-account DCSync, cert-based NTDS (certsync), or
ticket forging (golden / diamond / silver / sapphire) — demonstrate the vector against ONE test account/principal,
then purge. No whole-domain NTDS dump, no golden-ticket persistence, no prod-DC VSS.

**6 · Trusts.** Enumerate direction / transitivity, classify intra- vs inter-forest, record SID-filtering /
selective-auth posture. Prove a filtering gap by forging for a TEST SID — do NOT traverse a production trust.

Throughout: enumerate read-only before every write · one test principal + one test host · approval-gate anything
that touches Tier-0 or production availability · revert from the ledger · redact · catalogue (don't fire) the
destructive variants (DCShadow, skeleton key, full ntds.dit, mass coercion).

---

## Extended arsenal — BloodHound edge → technique reference
Each edge → the abuse, the variant skill, and the benign/reversible proof. See `refs/ad_commands.md` for commands.

| BloodHound edge | Abuse | Skill | Benign proof + revert |
|---|---|---|---|
| AdminTo / HasSession | local admin / creds resident on the host | ad-lateral-movement | PtH + benign cmd; purge |
| CanRDP / CanPSRemote / SQLAdmin | interactive / exec channel | ad-lateral-movement | one benign cmd; close session |
| MemberOf + AddMember / AddSelf | add self to a privileged group | ad-acl-abuse | add → verify → remove |
| ForceChangePassword | reset a user's password | ad-acl-abuse | reset (capture old) → act → restore |
| GenericAll / GenericWrite (user) | shadow-cred / targetedKerberoast / AS-REP UAC-flip | ad-acl-abuse | shadow-cred NT (quiet) → remove key |
| GenericAll / GenericWrite (computer) | shadow-cred (NT, no reboot) or RBCD | ad-acl-abuse | shadow-cred → remove; or RBCD → flush |
| AddKeyCredentialLink | msDS-KeyCredentialLink → PKINIT → NT | ad-acl-abuse | add link → auth → remove link |
| WriteDacl / WriteOwner / Owns | take ownership → grant rights → act | ad-acl-abuse | grant ACE → act → remove ACE + restore owner |
| AllExtendedRights | = ForceChangePassword (user) / DCSync (domain head) | ad-acl-abuse | as the mapped primitive |
| AllowedToDelegate | constrained S4U2proxy | ad-kerberos | S4U to a test SPN; purge ticket |
| AllowedToAct (RBCD) | write msDS-AllowedToActOnBehalfOf → S4U | ad-acl-abuse | RBCD → S4U → flush attribute |
| ReadLAPSPassword | read the host's local-admin password | ad-acl-abuse | read one → redact to fp |
| ReadGMSAPassword | compute the gMSA managed password → NT | ad-acl-abuse | read → redact; remove any added membership |
| DCSync (GetChanges + GetChangesAll) | replicate secrets | ad-acl-abuse | SINGLE test account only; APPROVAL-GATED |
| Enroll / ADCS (ESC*) | issue an auth cert as a target | ad-adcs | cert → PKINIT → REVOKE |
| HasSIDHistory | standing cross-domain rights | ad-context | enumerate + report (do NOT write) |
| TrustedBy | trust traversal | ad-context / ad-kerberos | forge for a TEST SID; feasibility only |
