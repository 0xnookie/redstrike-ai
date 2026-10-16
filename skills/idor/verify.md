# IDOR — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the IDOR gauntlet. Confirmed = identity A obtained/changed identity B's
resource because the ownership check is missing. Re-run A's session against B's id.

## IDOR false-positive gauntlet (base check #3)
- [ ] **Cross-OWNER, two identities.** The PoC shows account A (its session/token) accessing or
      modifying a resource owned by a DIFFERENT account B — evidenced with both identities. Accessing
      your OWN resource, or shared/public data, is not IDOR.
- [ ] **Ownership check genuinely missing.** The server returned B's data to A (not a 403/empty) — a
      real authorization gap, not a resource that is intentionally shared.
- [ ] **Data is B's, confirmed.** The returned data demonstrably belongs to B (a value only B's
      resource has), not a coincidental same-shaped response.
- [ ] **Mass-assignment (if claimed) took effect.** The privileged field the client set actually
      changed server state (e.g. `role` became admin) — verified by reading it back.
- [ ] **Test accounts; reversible; scope.** Both A and B are tester-controlled; any modification was
      on a test resource and reversible; in scope.

## CVSS integrity
Horizontal access to another user's data → High (`C:H`); write/account-takeover via mass-assignment →
Critical. Rate by what A could actually do to B's data.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "idor-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["A's token + GET /api/orders/{B_id} returned B's order (B-only address); 200 not 403; both test accounts"],
  "scope_ok": true, "notes": "test accounts A/B; no real-user data accessed" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
