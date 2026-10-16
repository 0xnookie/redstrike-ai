# Active Directory methodology (shared by the AD variants)
# Internal / assumed-breach. Authorized foothold REQUIRED. High-impact — exploitation is approval-gated.

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
