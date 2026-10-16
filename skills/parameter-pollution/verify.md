# HTTP Parameter Pollution — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the HPP gauntlet. Confirmed = a duplicated/polluted parameter changed a
security-relevant decision via a parser discrepancy. Re-run the benign payload.

## HPP false-positive gauntlet (base check #3)
- [ ] **A security decision actually changed.** The PoC shows the polluted parameter flipping an authz
      check, an identity, a price/amount, a redirect target, or smuggling a payload past a filter — not a
      cosmetic "which value echoes" curiosity.
- [ ] **Parser discrepancy is the mechanism.** Evidence that one layer (gateway/WAF/validator) read one
      occurrence and the backend acted on another (or last-wins/first-wins/array coercion) — the
      discrepancy is named, not assumed.
- [ ] **Not better owned elsewhere.** If HPP merely delivers SQLi/SSRF/XSS/smuggling, the finding is the
      delivered bug confirmed by THAT agent's rules; HPP is the vector note. Pure authz/value override via
      duplication is the HPP finding itself.
- [ ] **Benign + test identities.** Decision flipped on test accounts; no real-account change without approval.
- [ ] **Scope.**

## CVSS integrity
Authn/authz bypass → High/Critical; payment/price manipulation or WAF bypass enabling a Critical bug →
High; rate-limit/validation bypass → Medium. Rate from the decision that changed.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "parameter-pollution-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["POST admin=false&admin=true -> backend (last-wins) granted admin while the validator read the first value; reproduced; test account"],
  "scope_ok": true, "notes": "parser discrepancy named (gateway first-wins vs PHP last-wins); benign" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
