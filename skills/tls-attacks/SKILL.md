# TLS/SSL Attacks Agent

> ATOMIC agent — TLS/SSL protocol + cipher + certificate weakness assessment (downgrade, weak config, cert flaws, named CVEs, STARTTLS/HSTS).
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval** (active vuln probes). Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** enumerate TLS endpoints (host:port, STARTTLS services) → scan protocols + ciphersuites (testssl.sh/sslscan/sslyze/nmap) → inspect the certificate (validity, hostname/chain, self-signed) → check named issues (Heartbleed/POODLE/ROBOT/BEAST/CCS/Raccoon) → check STARTTLS stripping + HSTS → confirm one concrete weakness benignly → rate → emit → review → verify.
- **TOOLS:** testssl.sh, sslscan, sslyze, `nmap --script ssl-enum-ciphers`, `openssl s_client`, `refs/tls_attacks.md`.
- **GOAL:** Confirm a concrete TLS/SSL weakness — weak protocol/cipher (SSLv3/TLS1.0-1.1, RC4, EXPORT, DES), a certificate flaw (expired, hostname/chain mismatch, self-signed accepted), a named issue (Heartbleed/POODLE/ROBOT/BEAST/CCS/Raccoon), STARTTLS stripping, or missing HSTS — with a benign read-only proof. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `tls_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = in-scope hosts/ports (from `host-discovery`) + `scope.yaml`. `refs/` = `tls_attacks.md`. Chains FROM `host-discovery`; chains TO `reporting` + `security-headers` (HSTS).
- **DECOMPOSITION:** n/a (atomic; per-issue checks in refs).

## Goal
Confirm a concrete TLS/SSL weakness with a benign read-only proof (scanner output / a controlled check). Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## What do we want
- The TLS endpoint(s) + negotiated protocols/ciphersuites (incl. STARTTLS services: SMTP/IMAP/POP3/FTP)
- The specific weakness: weak protocol/cipher, certificate flaw, a named issue (Heartbleed/POODLE/ROBOT/BEAST/CCS/Raccoon), STARTTLS stripping, or missing HSTS
- A benign proof: scanner evidence a weak suite/protocol actually negotiates, a cert-validation failure shown, or a controlled non-destructive vuln check (e.g. a benign Heartbleed probe returning a small over-read) — NOT mass memory exfiltration

## Steps  (action · tool · output)
1. Enumerate TLS endpoints + STARTTLS services · host-discovery + refs · `tls_tests.jsonl`
2. Scan protocols + ciphersuites (testssl.sh / sslscan / sslyze / `nmap --script ssl-enum-ciphers`) · scanner · `tls_tests.jsonl`
3. Flag weak config: SSLv3/TLS1.0/1.1 enabled, RC4/EXPORT/DES/NULL, weak DH/keys · refs · `tls_tests.jsonl`
4. Inspect the certificate: expiry, hostname/SAN match, chain/trust, self-signed accepted · scanner · `tls_tests.jsonl`
5. Check named issues: Heartbleed (CVE-2014-0160), POODLE, ROBOT, BEAST, CCS (CVE-2014-0224), Raccoon · refs · `tls_tests.jsonl`
6. Check STARTTLS stripping + missing/weak HSTS · refs · `tls_tests.jsonl`
7. Confirm one concrete weakness benignly (scanner evidence / controlled check) · scanner · `poc/<id>/`
8. Rate (CVSS) + write finding · synth · `findings.json`
9. Emit report · synth · `report.md` · 10. /REVIEW · `review.md` · 11. /VERIFY · `verify.md`

## Tools
- testssl.sh, sslscan, sslyze, `nmap --script ssl-enum-ciphers`, `openssl s_client`, `refs/tls_attacks.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- In-scope hosts/ports (from `host-discovery`) + STARTTLS services, `scope.yaml`

## Outputs
`tls_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic, read-only):** protocol/cipher/cert scan + weak-config + cert-flaw detection.
- **Phase 2 (target-specific):** named-issue checks (Heartbleed/ROBOT/…) + benign confirmation + rating (approval-gated for active probes).

## Safety
The scan itself is read-only. Active vulnerability checks are **approval-gated**: a Heartbleed probe reads
only a SMALL, controlled over-read to confirm the leak (**never** loop to exfiltrate memory / secrets);
ROBOT/CCS/POODLE checks send a bounded number of benign handshakes. No DoS, no credential capture, no mass
memory pull. **Redact** any bytes an over-read returns. Scope-gate (in-scope host:port only); rate-limit;
audit-log; honor the kill switch. HSTS header-policy depth → `security-headers`.
