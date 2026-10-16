# Security Headers — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.
# The dominant failure mode here is SEVERITY INFLATION — automated header scanners cry wolf.
# Be the skeptic: a missing header is only a finding if it enables a CONCRETE attack in THIS app.

Run the 7 base checks + the header gauntlet.

## Header false-positive gauntlet (base check #3)
- [ ] **Concrete attack path, not best-practice.** Each reported item names a real, contextual
      exploit it enables here — e.g. missing/weak CSP AND a reflected-input sink; missing HSTS AND the
      site is reachable over http with no redirect; missing `X-Content-Type-Options` AND a sniffable
      user-controlled upload. "Header absent" with no path ⇒ Info at most, usually not a finding.
- [ ] **Not someone else's finding.** XFO/frame-ancestors → defer to `clickjacking`; ACAO → `cors`;
      CSP-as-XSS-defense → `xss-*`. Report the HEADER posture, don't double-count their vulns.
- [ ] **Severity is honest.** No `Medium`/`High` for a bare missing header without a demonstrated
      consequence. Cookie missing `HttpOnly` matters only with an XSS to pair it with (note the pairing).
- [ ] **Evidence present.** `headers.json` shows the actual (absent/weak) header for the cited page.
- [ ] **In scope.**

## CVSS integrity
Default these to Info/Low. Elevate ONLY with the concrete path spelled out and evidenced. Reject
inflation — this reviewer's main job is to keep the report credible.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "security-headers-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["missing HSTS + http served with no redirect -> MITM downgrade path; rated Low, evidenced"],
  "scope_ok": true, "notes": "demoted 4 best-practice 'missing header' items to info/omitted (no path)" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run (usually: down-rate or drop).
