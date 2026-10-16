# Credential access reference (authorized testing)
# Offline cracking only; online guessing is rate-limited + lockout-aware. REDACT every real secret to a
# fingerprint. Benign proof = ONE weak/test credential. Delete collected hash material afterward.

## 1. Online guessing (rate-limited, lockout-aware — policy FIRST)
Read the account-lockout / rate policy before any attempt; keep attempts well under the threshold and
spread over time. `hydra` / `medusa` support the common services (SSH, FTP, RDP, SMB, HTTP form,
databases). For an HTTP login, model the success/failure condition on the app's own response string.
Prefer a tiny, targeted list (known-weak defaults + a handful of policy-shaped guesses) over bulk spraying.
On AD, do policy-first spraying (one password across users, spaced) — never iterate many passwords per user.

## 2. Offline hash cracking
Identify the hash type first (`name-that-hash` / `hashid`). Then crack with `hashcat` or `john`, escalating:
wordlist → wordlist+rules → mask → targeted.

Common `hashcat` modes (reference):
| mode | hash |
|---|---|
| 0 | MD5 |  100 | SHA1 |  1400 | SHA256 |  1700 | SHA512 |
| 1000 | NTLM |  3200 | bcrypt |  1800 | sha512crypt |  500 | md5crypt |
| 13100 | Kerberos TGS-REP (RC4) |  18200 | Kerberos AS-REP |  5600 | NetNTLMv2 |  2100 | DCC2/MsCache2 |
| 22000 | WPA-PBKDF2/PMKID |  16500 | JWT |

Rules: `best64.rule` first, then `OneRuleToRuleThemAll`. Masks: `?u?l?l?l?l?d?d?s` style for policy-shaped
passwords. `john --format=<fmt> --wordlist=<w> --rules`. Keep a cracked value only as a fingerprint.

## 3. Credential stores on a landed host (authorized)
On an authorized, in-scope host you may review credential stores to show exposure. Techniques (described,
not scripted here): dumping the local account database / cached logon secrets, reading the directory
database on a domain controller, reading OS credential vaults, and recovering keys/tokens from user
profiles. Use the standard tooling for the platform; **redact** everything recovered, demonstrate the
exposure with a single benign proof, and delete any dumped material (record in `cleanup.md`). This step is
approval-gated and must stay within the engagement's host scope.

## 4. Benign proof + hygiene
Prove exactly ONE weak/recovered credential (authenticate once with it, or match it to a known test
account). Store secrets as fingerprints (e.g. a hash prefix + length), never plaintext. Rate the finding by
what the credential unlocks (reuse across hosts/services, privilege). Hand confirmed creds to
`ad-lateral-movement` only under approval. Delete wordlists/hash files you created.

---
## Extended arsenal — hashcat mode reference (expanded)
Identify the hash first (`name-that-hash` / `hashid`), then pick the mode. Crack is OFFLINE; recover ONE
proof credential, store it REDACTED, then delete the hash file + potfile.

Windows / Active Directory:
| mode | hash | mode | hash |
|---|---|---|---|
| 1000 | NTLM | 3000 | LM |
| 5500 | NetNTLMv1 | 5600 | NetNTLMv2 |
| 13100 | Kerberos TGS-REP RC4 (Kerberoast) | 18200 | Kerberos AS-REP (RC4) |
| 19600 | Kerberos TGS-REP AES128 | 19700 | Kerberos TGS-REP AES256 |
| 1100 | Domain Cached Creds (DCC / MS-Cache v1) | 2100 | Domain Cached Creds 2 (DCC2 / MS-Cache v2) |

*nix / generic / KDF:
| mode | hash | mode | hash |
|---|---|---|---|
| 0 | MD5 | 100 | SHA1 |
| 1400 | SHA256 | 1700 | SHA512 |
| 500 | md5crypt ($1$) | 400 | phpass / WP / Joomla |
| 7400 | sha256crypt ($5$) | 1800 | sha512crypt ($6$) |
| 3200 | bcrypt ($2*$) | 8900 | scrypt |
| 34000 | argon2 (recent builds — verify: `hashcat --help \| grep -i argon`) | | |

Archives / documents / managers:
| mode | hash | mode | hash |
|---|---|---|---|
| 13400 | KeePass 1/2 (.kdb/.kdbx) | 11600 | 7-Zip |
| 13600 | WinZip AES | 17200/17210/17220/17225 | PKZIP variants |
| 12500 | RAR3-hp | 13000 | RAR5 |
| 9400 | Office 2007 | 9500 | Office 2010 |
| 9600 | Office 2013/2016/2019 | 9700-9810 | legacy Office 97-2003 (RC4) |
| 10400 | PDF 1.1-1.3 | 10500 | PDF 1.4-1.6 |
| 10600 | PDF 1.7 L3 | 10700 | PDF 1.7 L8 (Acrobat X) |

Disk / OS / keys / directory:
| mode | hash | mode | hash |
|---|---|---|---|
| 14600 | LUKS (newer builds split into 29511-29543) | 16700 | FileVault 2 / APFS |
| 7100 | macOS 10.8+ (PBKDF2-SHA512) | 22911-22951 | SSH private key (sub-mode by cipher) |
| 111 | {SSHA} LDAP (SSHA-1, base64) | 1411 | {SSHA256} |
| 1711 | {SSHA512} | 16500 | JWT (HS*) |
| 22000 | WPA-PBKDF2 / PMKID | | |

---
## Extended arsenal — john the ripper format notes
```
# john uses NAMED formats (not numeric). List then crack:
john --list=formats | tr ',' '\n' | grep -i <keyword>
john --format=netntlmv2 --wordlist=<w> --rules=best64 hashes.txt
john --format=krb5asrep ...      # AS-REP          john --format=krb5tgs ...   # Kerberoast
john --format=NT ...  (NTLM)     john --format=mscash2 ...   # DCC2
# Extractors ("*2john") turn a protected file into john/hashcat input — REDACT & delete the file after:
zip2john a.zip > h   ;  rar2john a.rar > h  ;  7z2john.pl a.7z > h
office2john doc.docx > h  ;  pdf2john.pl f.pdf > h  ;  keepass2john db.kdbx > h
ssh2john id_rsa > h  ;  luks2john disk.img > h  ;  bitlocker2john -i disk.img > h
john --show hashes.txt            # recover after a crack; keep ONLY a fingerprint, then delete h + potfile
```

---
## Extended arsenal — rule + mask escalation strategy
```
# Escalate cost gradually; STOP as soon as ONE proof credential is recovered.
# 1) Fast wordlist pass:
hashcat -m <mode> h.txt <wordlist>
# 2) Wordlist + rules (cheap, high yield):
hashcat -m <mode> h.txt <wordlist> -r rules/best64.rule
hashcat -m <mode> h.txt <wordlist> -r rules/<large-ruleset>.rule        # bigger ruleset = more time
# 3) Targeted masks for policy-shaped passwords:
hashcat -m <mode> h.txt -a 3 '?u?l?l?l?l?l?d?d?s'                       # Upper+5lower+2digit+symbol
hashcat -m <mode> h.txt -a 3 '<Company>?d?d?d?d'                         # company name + 4 digits
hashcat -m <mode> h.txt -a 6 <wordlist> '?d?d?s'                         # hybrid: word + suffix
# 4) Custom charsets / keyspace shaping:
hashcat -m <mode> h.txt -a 3 -1 '?u?l' '?1?l?l?l?l?d?d!'
# Benign discipline: OFFLINE on authorized material; recover ONE proof; record REDACTED; delete hash file +
# potfile (cleanup.md).
```

---
## Extended arsenal — host credential-store locations (where to look -> redact everything)
Descriptive map only. Use the PLATFORM'S OWN standard tooling, require the proper authorization/privilege,
REDACT every value to a fingerprint, and prove exposure with ONE benign check — do NOT mass-dump.

| Store | Where it lives | Retrieve with | Handling |
|---|---|---|---|
| Local accounts (SAM) + system secrets (LSA) | registry hives (SAM/SECURITY/SYSTEM) | OS's standard secrets tooling; needs local admin/SYSTEM | redact; single-proof, no bulk export |
| Live logon secrets | LSASS process memory (in-memory only) | standard, EDR-aware tooling; highly sensitive | avoid touching memory unless approved; demonstrate, don't harvest |
| Cached domain logons (DCC2) | SECURITY hive | export -> OFFLINE crack (-m 2100) | redact; delete material after |
| Windows stored creds / DPAPI blobs | Credential Manager / Vault; master keys under the user profile | standard DPAPI/vault tooling | redact; one proof |
| Browser credentials | per-profile credential store (DPAPI/keychain-protected) | the browser's own credential tooling | redact; one proof |
| SSH keys / config | `~/.ssh/` (id_*, config, known_hosts) | read-only review; encrypted keys -> OFFLINE crack | redact passphrases |
| Linux secret service | session keyring / libsecret / gnome-keyring | `secret-tool` (standard) | redact |
| macOS keychain | `login.keychain-db` | `security(1)` (standard) | redact |
| Local *nix hashes | `/etc/shadow` (root) | read -> OFFLINE crack (`unshadow`) | redact |
| Cloud CLI token caches | `~/.aws/credentials`, `~/.aws/sso/cache`, `~/.config/gcloud/`, `~/.azure/` | read-only review | redact; ONE benign identity call max -> hand to cloud skill |
| Kube config | `~/.kube/config` (tokens/certs) | read-only review | redact; hand to k8s skill |
| Git / registry creds | `~/.git-credentials`, `~/.netrc`, `~/.docker/config.json` | read-only review | redact |
| CI / env secrets | environment variables, CI job logs, `.env`, mounted secret files | read-only review | redact; note exposure |
| Memory / swap / core dumps | process memory, swap, crash dumps | awareness-level | don't harvest; note that plaintext may reside here |

---
## Extended arsenal — online-guessing service matrix (lockout-safe)
```
# POLICY FIRST — read lockout/rate limits; keep attempts WELL under threshold; spread over time; use a tiny
# targeted list (known defaults + a few policy-shaped guesses), NOT bulk. Prefer ONE password across users.
hydra -L users.txt -p '<OneGuess>' -t 4 -W 5 <service>://<t>        # one password, many users; slow, few threads
hydra -l <user> -P tiny.txt -t 1 ssh://<t>                          # a HANDFUL of guesses only
# HTTP form — model success/failure on the app's OWN response string:
hydra -L u.txt -p '<OneGuess>' <t> http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid credentials"
medusa -h <t> -U u.txt -p '<OneGuess>' -M <module> -t 1            # medusa equivalent (one password sweep)
```

| Service | hydra module | medusa module | lockout note |
|---|---|---|---|
| SSH | `ssh` | `ssh` | key-auth may bypass; still rate-limited |
| FTP | `ftp` | `ftp` | often no lockout — still go slow |
| RDP | `rdp` | `rdp` | AD lockout applies — prefer policy-first spray |
| SMB | `smb` | `smbnt` | HIGH lockout risk — prefer `nxc` policy-first spray |
| HTTP basic | `http-get` / `http-head` | `http` | app/WAF rate limits |
| HTTP form | `http-post-form` / `https-post-form` | `web-form` | model on response string |
| LDAP | `ldap2` / `ldap3` | — | AD lockout applies |
| MSSQL | `mssql` | `mssql` | SQL + AD lockout |
| MySQL | `mysql` | `mysql` | — |
| PostgreSQL | `postgres` | `postgres` | — |
| VNC | `vnc` | `vnc` | often blacklists on fails |
| SMTP/POP3/IMAP | `smtp`/`pop3`/`imap` | `smtp`/`pop3`/`imap` | provider throttling |
| SNMP | `snmp` | `snmp` | community-string guessing, go slow |
| Telnet | `telnet` | `telnet` | slow; banner-based success |

Benign close-out: confirm exactly ONE weak credential (authenticate once), store it as a fingerprint, and
delete the lists/logs you created (record in `cleanup.md`).
