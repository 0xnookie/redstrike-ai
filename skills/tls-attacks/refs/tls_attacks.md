# TLS/SSL attacks reference (protocol / cipher / certificate / named issues)
# Scan is read-only; active vuln checks are approval-gated + BENIGN (bounded handshakes, a SMALL controlled
# over-read only). No DoS, no memory-exfil loop, no credential capture. REDACT any bytes an over-read returns.

## Protocol + cipher scan (start here, read-only)
```
# testssl.sh (comprehensive): ./testssl.sh --warnings off https://host:443
# sslscan:   sslscan --no-colour host:443
# sslyze:    sslyze --regular host:443
# nmap:      nmap -p443 --script ssl-enum-ciphers host     # grades each suite A..F
# openssl:   openssl s_client -connect host:443 -tls1       # does an old protocol complete a handshake?
```

## Weak configuration (downgrade surface)
```
# Flag as weak when ENABLED + negotiable:
#   Protocols: SSLv2, SSLv3 (POODLE), TLS 1.0 / TLS 1.1 (deprecated).
#   Ciphers:   RC4, EXPORT (40/56-bit), DES/3DES (SWEET32), NULL/anon, weak/export DH (Logjam), <2048-bit RSA.
#   Downgrade: missing TLS_FALLBACK_SCSV; insecure renegotiation; weak cert signature (MD5/SHA-1).
# A downgrade finding needs the weak option to actually negotiate (handshake completes), not merely be listed.
```

## Certificate flaws
```
# Inspect:  openssl s_client -connect host:443 | openssl x509 -noout -text -dates -subject -issuer
#   Expired / not-yet-valid (notBefore/notAfter).
#   Hostname/SAN mismatch (CN/SAN != host).
#   Untrusted / broken chain; self-signed accepted by the app/client.
#   Weak key (<2048 RSA), weak sig alg (MD5/SHA-1), over-scoped wildcard.
# Impact depends on whether a client/app actually accepts the invalid cert (test honestly).
```

## Named issues (version/config-gated; confirm benignly)
```
# Heartbleed (CVE-2014-0160): OpenSSL heartbeat over-read. Benign check only:
#   nmap -p443 --script ssl-heartbleed host       (reports vulnerable + a SMALL sample)
#   testssl.sh --heartbleed host                   -> confirm; do NOT loop to exfiltrate memory; REDACT bytes.
# POODLE: SSLv3 CBC padding oracle -> if SSLv3+CBC enabled.    testssl.sh --poodle
# ROBOT: RSA PKCS#1 v1.5 oracle (Bleichenbacher).             testssl.sh --robot   (benign oracle probe)
# BEAST: TLS1.0 CBC IV predictability -> if TLS1.0 enabled.   (client-side; note as config)
# CCS Injection (CVE-2014-0224): early ChangeCipherSpec.       nmap --script ssl-ccs-injection ; testssl.sh --ccs
# Raccoon: TLS-DH timing (static/reused DH keys).              config-gated; note DH reuse.
# SWEET32 (3DES), Logjam (export DH), FREAK (export RSA): surfaced by the suite scan above.
```

## STARTTLS stripping + HSTS
```
# STARTTLS (SMTP:25/587, IMAP:143, POP3:110, FTP:21): confirm TLS is actually enforced; a MITM that strips the
#   STARTTLS upgrade downgrades to cleartext. Check: testssl.sh -t smtp host:587 ; openssl s_client
#   -starttls smtp -connect host:587. Finding = upgrade not enforced / strippable.
# HSTS: missing/weak Strict-Transport-Security enables SSL-strip on the web layer. Record the TLS-layer fact
#   here; header-policy depth (max-age/includeSubDomains/preload) is `security-headers`.
```

## Benign-PoC rule
- Proof = read-only scanner evidence that the weak protocol/cipher actually negotiates, a shown cert-validation
  failure, or a BOUNDED benign check for a named issue (e.g. one Heartbleed probe returning a small over-read,
  bytes REDACTED). NEVER loop to exfiltrate memory, capture credentials, or DoS the endpoint. Rate what is
  exploitable, not merely supported.

---

## Extended arsenal — additional named issues (benign check + config precondition)
```
# DROWN (CVE-2016-0800): SSLv2 cross-protocol RSA decryption.
#   Precondition: the server's RSA key is reachable on ANY host/service that still speaks SSLv2 (even a different box).
nmap -p443 --script sslv2-drown host            # reports SSLv2 + key-reuse hints
testssl.sh --drown host:443                      # flags SSLv2 + shared-key exposure
#   Verdict only if SSLv2 actually negotiates somewhere the key is shared; TLS-only + unique key => not exploitable.

# Ticketbleed (CVE-2016-9244): F5 BIG-IP session-ticket memory over-read (Heartbleed-class, via Session ID).
#   Precondition: F5 BIG-IP front end with non-default Session Tickets. Bounded benign probe, REDACT bytes, do NOT loop:
testssl.sh --ticketbleed host:443                # one probe returns up to ~31 bytes of memory -> redact; one is enough.

# Lucky13 (CVE-2013-0169): CBC MAC-timing padding oracle. Precondition: CBC suites negotiable.
testssl.sh --lucky13 host:443                    # remote exploitation is timing-hard -> rate Low unless CBC is the only option.

# SLOTH (CVE-2015-7575): MD5/weak signatures accepted in the TLS1.2 handshake -> transcript-collision forgery.
#   Precondition: server signs with RSA+MD5 when offered. Detect via the handshake sig-alg list (may need @SECLEVEL=0):
openssl s_client -connect host:443 -sigalgs RSA+MD5 -cipher 'DEFAULT@SECLEVEL=0' </dev/null 2>&1 | grep -iE "Peer sign|handshake fail"
#   Handshake COMPLETES with only RSA+MD5 offered => MD5 sigs accepted; a clean failure => not accepted.

# ROCA (CVE-2017-15361): factorable RSA keys from a flawed keygen library.
testssl.sh host:443 | grep -i roca               # full run flags a ROCA-vulnerable key
openssl s_client -connect host:443 </dev/null | openssl x509 -noout -modulus   # extract modulus for the offline ROCA fingerprint test
#   Precondition: key generated by the affected smartcard/TPM library. A confirmed-vulnerable key => private key recoverable.

# CBC padding variants -- Zombie POODLE / GOLDENDOODLE / Sleeping POODLE / 0-length-record:
#   distinguishable responses to manipulated CBC padding/MAC = a decryption oracle. Precondition: TLS1.0-1.2 CBC negotiable.
testssl.sh host:443 | grep -iE "POODLE|GOLDENDOODLE|CBC"   # each reported by name; named-vulnerable => decryptable. No exfil loop.

# Insecure renegotiation (CVE-2009-3555) -- two distinct facts:
openssl s_client -connect host:443 </dev/null 2>&1 | grep -i "Secure Renegotiation"   # (a) IS NOT supported => MITM plaintext-injection surface
testssl.sh --renegotiation host:443              # (b) client-initiated reneg = DoS amplification -> CATALOGED, NOT fired
#   In an s_client session typing 'R'<enter> triggers ONE reneg; confirm accepted, then stop. NEVER loop (DoS).

# Terrapin (CVE-2023-48795): SSH transport (port 22), NOT TLS -- include only if SSH is in scope (awareness).
nmap -p22 --script ssh2-enum-algos host          # list kex/cipher/mac
#   Vulnerable precondition: chacha20-poly1305@openssh.com OR *-cbc + *-etm@openssh.com offered AND KEXINIT lacks
#   kex-strict-{c,s}-v00@openssh.com (strict-kex). Read-only enumeration only.

# ALPACA (cross-protocol content confusion) -- awareness/deployment, read-only:
openssl s_client -connect host:443 </dev/null | openssl x509 -noout -ext subjectAltName   # compare SAN/key across services
#   Finding = the same cert/key reused on a non-HTTP TLS service (FTPS/SMTPS/IMAPS) without ALPN/SNI strictness, letting a
#   MITM redirect an HTTPS session to a service that reflects attacker content. No exploitation fired.
```

---

## Extended arsenal — protocol/cipher negotiation -> severity decision table
Severity = EXPLOITABILITY, not mere support. "Negotiates" = the handshake actually completes with that option
(confirm it, never infer from a capability/offered line). Rate from the benign confirmation, then stop.

| Negotiated (handshake completes) | Severity if exploitable | Exploit precondition | Benign confirmation |
|---|---|---|---|
| SSLv2 | Critical | RSA key shared with any SSLv2 host -> DROWN decrypt | `testssl.sh --drown host:443` / `nmap -p443 --script sslv2-drown host` |
| SSLv3 + CBC | High | attacker forces fallback -> POODLE oracle | `testssl.sh --poodle host:443` |
| TLS1.0 + CBC | Medium | client-side BEAST; deprecated downgrade surface | `openssl s_client -tls1 -connect host:443` |
| TLS1.1 | Low-Med | deprecated; downgrade surface | `openssl s_client -tls1_1 -connect host:443` |
| RC4 | High | keystream bias -> plaintext recovery over many sessions | `testssl.sh --rc4 host:443` |
| 3DES/DES (64-bit block) | Medium | SWEET32 birthday collision; needs huge same-key traffic | `testssl.sh --sweet32 host:443` |
| EXPORT RSA (<=512-bit) | High | FREAK: force export RSA, factor the key | `testssl.sh --freak host:443` |
| EXPORT/weak DH (<=1024) | High | Logjam: downgrade + precomputed discrete log | `testssl.sh --logjam host:443` |
| NULL / anon suite | Critical | no encryption / no server auth -> trivial MITM | `nmap -p443 --script ssl-enum-ciphers host` |
| Static-RSA kex (TLS_RSA_*) | Medium | no PFS (passive decrypt if key leaks); ROBOT if padding oracle | `testssl.sh --robot host:443` |
| CBC (TLS1.0-1.2) | Low-Med | Lucky13 / padding-variant oracle (timing, hard remote) | `testssl.sh --lucky13 host:443` |

---

## Extended arsenal — certificate depth (chain / CT / revocation / constraints / key-reuse)
```
# Full chain build + trust-store validation:
openssl s_client -connect host:443 -showcerts </dev/null                       # dump the presented chain
openssl s_client -connect host:443 -verify_return_error \
  -CAfile /etc/ssl/certs/ca-certificates.crt </dev/null 2>&1 | grep "Verify return code"
#   0 (ok) = trusted; 20 = unable to get local issuer (missing intermediate); 19/18 = self-signed in chain.

# CT-log presence (SCTs embedded in the cert):
openssl s_client -connect host:443 </dev/null | openssl x509 -noout -text | grep -A3 "CT Precertificate SCTs"
#   Absent SCTs => may be un-logged (modern clients can distrust). Cross-check the key/serial against public CT logs.

# OCSP stapling + manual OCSP + CRL revocation:
openssl s_client -connect host:443 -status </dev/null 2>&1 | grep -A17 "OCSP Response"   # is a response stapled?
openssl s_client -connect host:443 </dev/null | openssl x509 -noout -ocsp_uri             # OCSP responder URL
openssl ocsp -issuer chain.pem -cert leaf.pem -url <ocsp_uri> -no_nonce                   # "good" / "revoked"
openssl x509 -in leaf.pem -noout -text | grep -A4 "CRL Distribution"                      # CRL DP -> fetch, check serial

# Name-constraints / EKU / Basic Constraints:
openssl x509 -in leaf.pem -noout -text | grep -A2 -E "Extended Key Usage|Name Constraints|Basic Constraints"
#   leaf must have EKU serverAuth; CA:TRUE on a leaf = dangerous; a private CA without nameConstraints = over-trust.

# Wildcard / SAN scope:
openssl x509 -in leaf.pem -noout -ext subjectAltName
#   over-broad '*.example.com' or stale SANs widen blast radius + ALPACA surface.

# Key reuse across hosts (same SPKI on many hosts = one key compromise -> many hosts; DROWN/ROBOT cross-service risk):
openssl s_client -connect host:443 </dev/null | openssl x509 -noout -pubkey \
  | openssl pkey -pubin -outform DER | openssl dgst -sha256                                # compare this SPKI hash across hosts

# Self-signed / invalid-cert acceptance -- test the CLIENT, not just the server:
#   openssl verify will fail, but the consuming app may ignore it. Confirm by observing the real client's behavior (benign):
#   does the app/API client complete the request over an untrusted cert? If yes => validation is effectively off.
```

---

## Extended arsenal — mTLS / client-certificate testing (read-only)
```
# Does the endpoint REQUEST a client cert, and is it OPTIONAL or REQUIRED?
openssl s_client -connect host:8443 </dev/null 2>&1 | grep -A3 "Acceptable client certificate CA names"
#   Connect WITHOUT a client cert:
#     handshake completes + app returns 200 => client cert OPTIONAL / not enforced -> authz gap if it is meant to gate access
#     handshake_failure / "certificate required" alert => REQUIRED
# Untrusted client-cert acceptance (benign, TEST cert only -- no real identity):
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=redstrike-test" -keyout ck.pem -out cc.pem
openssl s_client -connect host:8443 -cert cc.pem -key ck.pem </dev/null 2>&1 | grep "Verify return code"
#   If a self-signed TEST client cert is ACCEPTED => broken client-cert validation (trust-store/chain not enforced).
```

---

## Extended arsenal — TLS 1.3 specifics (downgrade sentinel / supported-versions / PFS / resumption / 0-RTT)
```
# Downgrade-protection sentinel: a 1.3-capable server negotiating <=1.2 sets ServerRandom's last 8 bytes to
#   44 4F 57 4E 47 52 44 ("DOWNGRD") + 01 (for 1.2) / 00 (for <=1.1) so a 1.3 client detects active downgrade.
testssl.sh host:443 | grep -i "downgrade"        # reports "Downgrade attack prevention: supported / NOT supported"

# supported_versions enforcement + PFS: confirm 1.3 actually negotiates and non-PFS suites are refused.
openssl s_client -connect host:443 -tls1_3 </dev/null 2>&1 | grep -E "Protocol|Cipher"   # must be TLSv1.3 + an ECDHE suite
testssl.sh --fs host:443                           # lists FS ciphers; flags any static-RSA (non-PFS) suite still offered

# Session-resumption hygiene (tickets vs PSK) -- a weak/static ticket key (STEK) breaks past-session confidentiality:
openssl s_client -connect host:443 -tls1_2 -reconnect </dev/null 2>&1 | grep -iE "New|Reused"   # "Reused" => resumption on
#   Prefer rotated ticket keys / TLS1.3 PSK with PFS. Record ticket lifetime; long-lived static tickets = exposure.

# 0-RTT (TLS1.3 early-data) replay awareness -- early-data is REPLAYABLE by design:
openssl s_client -connect host:443 -tls1_3 -sess_out sess.pem </dev/null        # capture a resumable session
printf 'GET / HTTP/1.1\r\nHost: host\r\nConnection: close\r\n\r\n' > ed.txt
openssl s_client -connect host:443 -tls1_3 -sess_in sess.pem -early_data ed.txt 2>&1 | grep -i "Early data"
#   "Early data was accepted" => 0-RTT active. Use ONLY an idempotent GET to confirm; NEVER replay a state-changing
#   request (transfer/order) -- that is the real risk, catalogued not fired.
```

---

## Extended arsenal — STARTTLS depth per protocol (strip / upgrade-not-enforced)
```
# For each service: (1) TLS must actually complete via STARTTLS, (2) the server must REFUSE credentials/data in cleartext
#   BEFORE the upgrade. A MITM that strips the capability line (e.g. removes "250-STARTTLS" from the EHLO reply) forces
#   cleartext. Finding = upgrade not enforced / strippable (we PROVE the gap benignly; we do NOT capture creds).
openssl s_client -starttls smtp -connect host:587 </dev/null     # TLS must complete
printf 'EHLO test\r\nQUIT\r\n' | nc host 587                      # cleartext: is STARTTLS advertised? is AUTH offered pre-TLS?
#   AUTH/LOGIN available before STARTTLS => cleartext-credential exposure when the capability line is stripped.
```

| Service | Port(s) | openssl s_client | testssl.sh |
|---|---|---|---|
| SMTP | 25 / 587 | `-starttls smtp` | `-t smtp` |
| IMAP | 143 | `-starttls imap` | `-t imap` |
| POP3 | 110 | `-starttls pop3` | `-t pop3` |
| FTP | 21 | `-starttls ftp` | `-t ftp` |
| LDAP | 389 | `-starttls ldap` | `-t ldap` |
| XMPP | 5222 / 5269 | `-starttls xmpp` / `-starttls xmpp-server` | `-t xmpp` |
| Postgres | 5432 | `-starttls postgres` | `-t postgres` |
| MySQL | 3306 | `-starttls mysql` | `-t mysql` |
| NNTP / Sieve / IRC | 119 / 4190 / 6667 | `-starttls nntp`/`sieve`/`irc` | `-t nntp` |

```
# Per-protocol one-liners (swap the token); nmap enumerates ciphers over STARTTLS automatically on known ports:
testssl.sh -t imap host:143
testssl.sh -t postgres host:5432
nmap -p25,587,110,143,21,389 --script ssl-enum-ciphers host     # grades suites behind STARTTLS too
# Finding tiers: no STARTTLS offered (cleartext only) > STARTTLS strippable / cleartext AUTH pre-TLS > weak suite behind TLS.
```
