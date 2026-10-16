# LDAP Injection — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the LDAP gauntlet. Confirmed = a filter injection manipulated the LDAP search
(auth bypass or over-broad enumeration). Re-run the benign payload.

## LDAP-injection false-positive gauntlet (base check #3)
- [ ] **Filter manipulation proven.** The PoC shows an injected filter metacharacter changing the search
      result — authenticated without valid creds, or a `*` returned entries the input shouldn't — not a
      500/error. The result change is the proof.
- [ ] **It's LDAP filter syntax.** The vector uses LDAP metachars (`)( * | & =`) reaching the directory
      search — not an app logic quirk.
- [ ] **Benign + minimal.** Auth bypass proven once; enumeration limited to a minimal marker — no bulk
      directory dump.
- [ ] **Blind (if used) reproducible.** The attribute-presence boolean differential is reproducible.
- [ ] **Scope + approval.**

## CVSS integrity
Auth bypass → High/Critical; directory enumeration (users/roles) → Medium/High. Justify from the demonstrated manipulation.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "ldap-injection-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["login user=*)(uid=*))(|(uid=* returned a valid session without a password; filter breakout confirmed; reproduced"],
  "scope_ok": true, "notes": "auth bypass proven once; no bulk enumeration; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
