# Host Header Injection — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the host-header gauntlet. Confirmed = attacker-controlled host reaches a
security-relevant sink. The headline is password-reset poisoning — re-drive it on a test account.

## Host-header false-positive gauntlet (base check #3)
- [ ] **Attacker-controlled host reaches a SECURITY-RELEVANT sink.** Not mere reflection of the Host
      somewhere benign — it must drive a reset link, an absolute redirect, a cache key, or routing.
      Evidence shows the attacker host in that sink (`poc/<id>/`).
- [ ] **Password-reset poisoning (if claimed) is real.** The reset email/link actually points to the
      injected host, so a victim clicking it would hand the token to the attacker. Re-driven on a test
      account.
- [ ] **The app trusts the header you overrode.** Identify WHICH header did it (`Host` vs
      `X-Forwarded-Host` …) — some are stripped by the edge; the one that worked must be reachable
      from the attacker's position.
- [ ] **Not benign reflection / not self-only.** The sink is consumed by a victim or the
      infrastructure, not just echoed in your own response.
- [ ] **In scope.**

## CVSS integrity
Password-reset poisoning → High (account takeover path). Cache poisoning via host → per blast radius.
A benign absolute-URL reflection with no exploit path → Low/Info. Justify from the confirmed sink.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "host-header-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["X-Forwarded-Host honored; reset email link host = attacker.example; token would leak on click"],
  "scope_ok": true, "notes": "test account; reset not sent to any real user" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
