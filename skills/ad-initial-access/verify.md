# AD Initial Access — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the initial-access gauntlet. Confirmed = unauth→first valid credential proven
benignly, secret redacted, no lockouts. Re-run the benign proof.

## AD-initial-access false-positive gauntlet (base check #3)
- [ ] **A valid credential was actually obtained.** A captured NetNTLMv2 cracked OFFLINE to a real/test
      account, OR a spray returned a confirmed valid login — demonstrated once — not "LLMNR is on" or "a hash
      was captured but not cracked" (an uncracked capture is at most an exposure note, lower severity).
- [ ] **Policy-safe.** Spraying was policy-first and lockout-aware; no real accounts were locked (evidenced).
      Poisoning was passive/time-boxed and stopped (`cleanup.md`).
- [ ] **Redacted.** The credential/hash is stored as a fingerprint, not plaintext.
- [ ] **Severity.** A privileged/widely-valid first credential → High; a low-priv single account → Medium.
- [ ] **Scope + approval.**

## CVSS integrity
Rate from what the first credential enables (domain reach), and whether it was truly unauth→credential.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "ad-initial-access-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["LLMNR poisoning captured a NetNTLMv2 for a test user; cracked offline to a weak password (fingerprint stored); authenticated once; no lockouts; poisoning stopped"],
  "scope_ok": true, "notes": "passive capture, offline crack, redacted; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
