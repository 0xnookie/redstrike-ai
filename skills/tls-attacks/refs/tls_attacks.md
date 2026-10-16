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
