# Open Redirect — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the open-redirect gauntlet. Confirmed = the redirect lands on an
attacker-controlled EXTERNAL origin — re-run with curl/browser and inspect where it lands.

## Open-redirect false-positive gauntlet (base check #3)
- [ ] **External + attacker-controlled destination.** The redirect goes to an origin YOU control
      (server 3xx `Location`, or a client-side `location`/`meta` redirect), evidenced in `poc/`.
      A same-site or relative redirect is not a finding.
- [ ] **Allowlist genuinely bypassed.** If the app validates the destination, the PoC shows the
      actual bypass (`//evil`, `target.com.evil`, `@`, `\`, CRLF, unicode) — not a payload the
      allowlist would have caught.
- [ ] **Impact rated honestly.** Open redirect ALONE is Low. Elevate ONLY with a demonstrated chain:
      OAuth/SSO token leak (redirect carries the code/token to your host), SSRF (server-side fetch of
      the param), or `javascript:`→XSS (client-side sink). No chain demonstrated ⇒ keep it Low.
- [ ] **Not a self-only / unreachable path.** Delivery = victim opens the crafted link (valid).
- [ ] **In scope.**

## CVSS integrity
Baseline open redirect ~`AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N` (Low). Any High/Critical requires the
chained-impact evidence (token theft shown, SSRF reaching internal, XSS executing). Reject inflation.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "open-redirect-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["302 Location -> https://evil.example confirmed; allowlist bypassed via //; no token leak => rated Low"],
  "scope_ok": true, "notes": "redirected to benign OOB host; no chain demonstrated" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
