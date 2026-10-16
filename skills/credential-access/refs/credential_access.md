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
