# GraphQL — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the GraphQL gauntlet. Confirmed = a GraphQL-specific flaw with impact. Re-run
the query and confirm the exposed data / bypass.

## GraphQL false-positive gauntlet (base check #3)
- [ ] **Impact, not just introspection-on.** Introspection enabled is Low/Info by itself — a finding
      needs a consequence (sensitive schema aiding a confirmed attack, or a data/authz issue). Rate
      introspection alone honestly.
- [ ] **Field-authz bypass returned restricted data.** A low-priv identity actually received a field/
      object a role shouldn't see (evidenced with two identities) — not just that the field exists.
- [ ] **Node IDOR cross-owner.** `node(id:)`/global-id access returned another owner's object (test
      accounts).
- [ ] **Arg injection confirmed by the injection agent.** Any SQLi/NoSQLi via resolver args is
      evidenced per the injection/sqli gauntlet (hand-off), not assumed.
- [ ] **DoS not executed.** Any DoS is reported as feasibility only — no resource-exhausting query was run.
- [ ] **Scope + test accounts.**

## CVSS integrity
Field-authz/node-IDOR exposing sensitive data → High; introspection-only → Low/Info. Justify from the
demonstrated exposure.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "graphql-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["low-priv query { user(id:B){ ssn } } returned B's ssn; field not authz-checked; two test accounts; no DoS run"],
  "scope_ok": true, "notes": "introspection also on (noted Low separately); no DoS executed" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
