# Business Logic — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.
# Hardest to verify: you must understand the INTENDED behavior to judge a violation. Read
# workflow_model.md + invariants.json first, then judge each finding against the stated invariant.

Run the 7 base checks + the business-logic gauntlet. Confirmed = an intended invariant was violated
with real impact, reproducibly.

## Business-logic false-positive gauntlet (base check #3)
- [ ] **A real invariant was broken.** The finding cites a specific invariant from `invariants.json`
      and shows it violated (e.g. paid less than price, got another user's resource, reused a one-time
      token, skipped a required step). "Unusual but intended" behavior is not a finding.
- [ ] **Concrete impact.** The violation yields money/access/data/quota advantage — not a cosmetic or
      theoretical oddity. Evidence in `poc/<id>/` (the altered request + the advantaged result).
- [ ] **Reproducible.** Re-running the abuse sequence reproduces the result (for races: reproduced
      across attempts, with the timing/parallelism noted).
- [ ] **Not another agent's bug mislabeled.** Pure object-reference access → access-control/IDOR;
      pure injection → the injection agents. Keep business-logic for invariant/workflow violations.
- [ ] **In scope; test accounts; reversible** (no real funds moved / real orders completed).

## CVSS integrity
Rate by business impact (free goods, privilege, fund movement). These often don't map cleanly to
CVSS — state the business impact explicitly alongside any vector. Justify from the evidenced advantage.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "business-logic-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["invariant 'price server-side' violated: negative quantity credited balance; reproduced x3; test account"],
  "scope_ok": true, "notes": "no real funds moved; order voided after confirm" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
