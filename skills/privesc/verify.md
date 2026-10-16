# Privilege Escalation — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.
# Read authz_context.json role_matrix FIRST — judge each finding against the INTENDED role.

Run the 7 base checks + the privesc gauntlet. Confirmed = a low-priv identity performed a function
the role matrix reserves for a higher role. Re-run the low-priv session against the privileged endpoint.

## Privesc false-positive gauntlet (base check #3)
- [ ] **Low-priv performed a higher-role action.** The PoC shows account A (low-priv) successfully
      invoking a function the matrix marks admin/higher-role — the action EXECUTED (state changed /
      privileged data returned), not a 403 or a no-op.
- [ ] **Genuinely higher privilege, per the matrix.** Cross-check `authz_context.json`: the endpoint
      is actually reserved for a higher role, not a capability A is intended to have.
- [ ] **Not IDOR mislabeled.** Function-level (any-low-priv-can-call-admin) vs object-level (access a
      specific other user's object) — reclassify to `idor` if it's really object scoping.
- [ ] **Effect confirmed.** For a state-changing admin action, the change is verified by reading it
      back; for data, the returned data is genuinely privileged.
- [ ] **Test account; benign/reversible action; approval; scope.**

## CVSS integrity
Vertical escalation to admin → High/Critical (`PR:L→`, `S:C` possible). Rate by the power gained.
Justify from the demonstrated privileged action.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "privesc-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["low-priv A POST /admin/users/role succeeded (200, role changed); matrix reserves it for admin; verified read-back; test account"],
  "scope_ok": true, "notes": "benign reversible action; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
