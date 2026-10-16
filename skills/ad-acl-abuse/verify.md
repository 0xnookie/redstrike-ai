# AD ACL Abuse — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the ACL-abuse gauntlet. Confirmed = an ACL edge was EXERCISED on a test target and
reverted. Guard the revert + single-account-DCSync limits.

## AD-ACL false-positive gauntlet (base check #3)
- [ ] **Edge exercised, not just present.** The PoC shows the abuse WORKING — a test user's password reset,
      a shadow credential added + PKINIT auth succeeded, a DACL granted + used, a group membership added —
      not merely that BloodHound shows the edge.
- [ ] **On a TEST principal.** The target was a tester-controlled/test object, not a real privileged
      account disrupted.
- [ ] **DCSync limited.** Any DCSync pulled a SINGLE test account to prove the right — NOT the whole domain
      or krbtgt. Flag a full domain dump.
- [ ] **Reverted.** Every change (password, DACL, membership, keyCredentialLink) is in `cleanup.md` and
      was reverted — the domain is back to its prior state.
- [ ] **Scope + approval.**

## CVSS integrity
An edge granting control of a privileged principal / DCSync right → Critical (domain compromise path).
Justify from the demonstrated abuse + where the edge leads (BloodHound path).

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "ad-acl-abuse-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["help-desk group has ForceChangePassword over a test user; reset it + logged in; reverted; path leads to Server Admins"],
  "scope_ok": true, "notes": "test principal; all changes reverted (cleanup.md); DCSync not used" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
