# NoSQL Injection — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the NoSQL gauntlet. Confirmed = an operator/syntax injection manipulated the
query (auth bypass or data differential). Re-run the benign payload.

## NoSQL false-positive gauntlet (base check #3)
- [ ] **Query manipulation proven.** The PoC shows an injected operator changing query behaviour — e.g.
      `user[$ne]=x&pass[$ne]=y` authenticated WITHOUT valid creds, or a `$regex`/`$gt` returned data the
      input shouldn't — not just a 500/error. The behaviour change is the proof.
- [ ] **It's NoSQL operator/syntax, not something else.** The vector is a NoSQL operator (`$ne`/`$where`/…)
      or syntax breakout reaching the DB — distinguished from an app logic bug.
- [ ] **Benign + minimal.** Auth bypass proven once; any extraction is a minimal marker — no bulk dump,
      no DB-hanging `$where`. 
- [ ] **Blind (if used) reproducible.** A `$where` time / `$regex` boolean differential is reproducible
      (controlled for jitter), not a one-off.
- [ ] **Scope + approval.**

## CVSS integrity
Auth bypass → High/Critical; data extraction → High. Justify from the demonstrated manipulation.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "nosql-injection-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["login with user[$ne]=x&pass[$ne]=y returned a valid session (authed as first user); no creds used; reproduced"],
  "scope_ok": true, "notes": "auth bypass proven once; no bulk extraction; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
