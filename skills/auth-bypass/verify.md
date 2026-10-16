# Authentication Bypass — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the auth-bypass gauntlet. Confirmed = an authenticated/privileged state (or a
required step) was reached WITHOUT completing the intended auth. Re-run the bypass.

## Auth-bypass false-positive gauntlet (base check #3)
- [ ] **Protected state reached without valid auth.** The PoC shows access to an authenticated/
      post-2FA/privileged resource WITHOUT valid credentials or without completing the required step —
      evidenced (authed content / action succeeded). A normal successful login is not a bypass.
- [ ] **The bypass is the cause.** The specific technique (forced-browse, flag tamper, 2FA skip,
      fixation, reset flaw) is what granted access, reproducibly — not a misconfigured test.
- [ ] **Not a client-only illusion.** A flipped client-side flag must result in SERVER-granted access
      (the server actually served protected data/performed the action), not just a UI change.
- [ ] **Benign + no real-user impact.** Test account; no real brute-force / lockouts; reset/MFA done
      on tester-controlled accounts; approved.
- [ ] **In scope.**

## CVSS integrity
Full auth bypass / 2FA bypass → High/Critical. Rate by what the bypass grants. Justify from evidence.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "auth-bypass-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["POST /verify-2fa skipped; GET /dashboard after step-1 login returned authed content; server-granted; test account"],
  "scope_ok": true, "notes": "no brute-force; test account; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
