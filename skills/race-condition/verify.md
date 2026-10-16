# Race Condition — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the race gauntlet. Confirmed = CONCURRENCY caused an intended invariant to break,
reproducibly, benignly. Re-run the benign, bounded burst.

## Race-condition false-positive gauntlet (base check #3)
- [ ] **The invariant actually broke.** The PoC shows a concrete break: a single-use/limited action
      succeeded N>1 times, a balance/stock became inconsistent, a unique constraint was duplicated, or a
      quota/rate-limit was overrun — evidenced by before/after STATE, not just HTTP 200s.
- [ ] **Concurrency is the cause.** The serial baseline does NOT reproduce it; only the parallel burst
      does. (A limit that's simply absent is a plain logic/authz bug for `business-logic`/`idor`, not a race.)
- [ ] **It's reproducible.** Re-firing the bounded burst breaks the invariant again (control for luck —
      races are probabilistic; a single success with a plausible mechanism + one reproduction is the bar).
- [ ] **Benign + minimal + reverted.** A test account, bounded concurrency (not a flood), and any state
      change was voided/refunded/deleted. No DoS, no real financial movement.
- [ ] **Severity matches impact.** Double-spend/withdrawal → High/Critical; coupon/quota overrun →
      Medium/High; vote/follow inflation → Low/Medium.
- [ ] **Scope + approval.**

## CVSS integrity
Rate from the demonstrated business impact of the broken invariant, not the mere existence of a race.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "race-condition-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["single-use coupon redeemed 4x via a 20-request single-packet burst; serial redemption is blocked (409); reproduced twice; test account; balance refunded"],
  "scope_ok": true, "notes": "bounded concurrency; state reverted; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
