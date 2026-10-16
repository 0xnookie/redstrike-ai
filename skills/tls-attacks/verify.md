# TLS/SSL Attacks — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the TLS gauntlet. Confirmed = a specific weak protocol/cipher/cert flaw or named
issue is evidenced on an in-scope endpoint by a benign read-only check. Re-run the scanner/check.

## TLS false-positive gauntlet (base check #3)
- [ ] **The weakness is actually negotiated/present.** The scanner shows the weak protocol/cipher is ENABLED
      and negotiable (e.g. TLS 1.0 + RC4 completes a handshake), the cert genuinely fails validation
      (expired / hostname mismatch / untrusted chain), or the named issue's check returns a positive — not a
      scanner "info"/"potential" line misread as confirmed.
- [ ] **Named issues are version/config-gated, not blanket-claimed.** Heartbleed/POODLE/ROBOT/BEAST/CCS/
      Raccoon are asserted only when the version + config are actually vulnerable and a benign check confirms
      it — not flagged merely because a scanner mentions the CVE.
- [ ] **Benign + redacted.** Any Heartbleed over-read is a SMALL controlled sample (no memory-exfil loop);
      any returned bytes are REDACTED; handshake probes are bounded; no DoS.
- [ ] **Right owner.** Missing-HSTS header-policy depth and other security-header nuance defer to
      `security-headers`; this skill keeps the TLS-layer facts.
- [ ] **Severity reflects exploitability.** A weak-but-not-negotiated suite or a cosmetic cert note is Low/
      Info; an exploitable downgrade, a memory-leaking Heartbleed, or an accepted invalid cert on a sensitive
      endpoint is higher.
- [ ] **Scope + approval.**

## CVSS integrity
Rate from real exploitability: confirmed Heartbleed memory leak / exploitable downgrade → High; a weak cipher
merely enabled → Medium/Low; cosmetic cert hygiene → Low/Info. Don't inflate "supported" into "exploited".

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "tls-attacks-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["testssl.sh negotiates TLS1.0 + TLS_RSA_WITH_RC4_128_SHA on 203.0.113.10:443 (handshake completed); weak cipher actually enabled, not an info line; in-scope host"],
  "scope_ok": true, "notes": "read-only scanner evidence; no DoS; HSTS depth deferred to security-headers; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
