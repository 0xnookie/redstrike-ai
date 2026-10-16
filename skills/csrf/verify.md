# CSRF — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the CSRF gauntlet. CSRF is confirmed by a cross-origin state change with
ambient creds — re-execute the PoC from an attacker origin in a victim session.

## CSRF false-positive gauntlet (base check #3)
- [ ] **Genuinely state-changing + security-relevant.** The request changes server state worth
      attacking (email/password change, role, funds, settings). A read or a trivial action is not it.
- [ ] **Cookie-based ambient auth.** Auth rides on cookies the browser auto-sends. If auth uses an
      `Authorization`/bearer header (not auto-sent cross-origin), there is NO CSRF — reject.
- [ ] **No effective token.** Either no anti-CSRF token, or the token is not validated — PROVE it by
      removing/replacing the token and the request still succeeds. A present, validated token ⇒ reject.
- [ ] **SameSite doesn't already block it.** Confirm cookies are actually sent in a real cross-site
      context (SameSite=None, or Lax with a top-level navigation GET). SameSite=Strict/Lax blocking
      the POST ⇒ not exploitable, reject/downgrade.
- [ ] **No other gate.** Not blocked by a required custom header / non-simple content-type that a
      cross-origin page cannot set, or an enforced Origin/Referer check.
- [ ] **PoC works cross-origin** in a victim session (evidence in `poc/<id>/`), not same-site.
- [ ] **In scope.**

## CVSS integrity
Rate by the action's impact (account takeover via email/password change → high; minor setting → low).
Typically `AV:N/AC:L/PR:N/UI:R/S:U/...`. Justify from the confirmed change.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "csrf-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["cookie-auth; token removal still succeeds; SameSite=None; PoC fired email change cross-origin"],
  "scope_ok": true, "notes": "test account used; change reverted" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
