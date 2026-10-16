# Clickjacking — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the clickjacking gauntlet. Confirmed = a SENSITIVE action on a FRAMEABLE page.

## Clickjacking false-positive gauntlet (base check #3)
- [ ] **Actually frameable.** No `X-Frame-Options` and no CSP `frame-ancestors` on the SENSITIVE
      route (not just the home page), or a demonstrated bypass. Evidence: the page renders inside the
      PoC iframe (`poc/<id>/`).
- [ ] **Sensitive, state-changing target.** The framed page has an action worth hijacking (delete,
      pay, grant, change email). A read-only/info page is NOT a real finding.
- [ ] **Redress is real.** The PoC shows the victim's click can be routed to the sensitive control
      (overlay/opacity/decoy) — not merely that the page frames.
- [ ] **No other mitigation.** Not defeated by SameSite (for the underlying request), a confirm
      step, or frame-busting JS that actually works.
- [ ] **In scope.**

## CVSS integrity
Usually Low–Medium, `UI:R` (requires victim interaction). Impact = the hijacked action. Don't rate a
frameable info page as a vuln.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "clickjacking-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["no XFO/frame-ancestors on /account/delete; renders in iframe; overlay routes click to Delete"],
  "scope_ok": true, "notes": "test account; action not actually triggered" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
