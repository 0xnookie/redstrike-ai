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
