# In-Band SQLi — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the in-band SQLi gauntlet. Confirmed = data returned via the injection
(error/union), not a coincidental error. Re-run the payload and confirm the marker comes back.

## In-band SQLi false-positive gauntlet (base check #3)
- [ ] **Injection returned DATA.** The PoC shows a value produced by the DB via the injection (e.g.
      `version()`, db name, a marker from `UNION SELECT`) in the response — not just a 500/error page.
      A generic error is a candidate, not a confirmed SQLi.
- [ ] **It's SQL, not another bug.** The marker is clearly SQL-sourced (DB version string, concat
      output), ruling out reflected input / app error coincidence.
- [ ] **Context + payload coherent.** The breakout matches the classified `query_context`; the union
      column count/types are correct and reproducible.
- [ ] **Read-only + minimal.** Proof is a benign marker / db metadata — NOT a dump of real PII or
      tables. If the executor dumped sensitive data, flag the over-collection.
- [ ] **Scope + approval.**

## CVSS integrity
In-band SQLi with data extraction is High/Critical (`C:H`, often `I:H` if writable). Justify from what
was demonstrably extractable — do not claim RCE/write without evidence.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "sqli-inband-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["string-context breakout; UNION SELECT returned 8.0.32 (version) in body; reproducible; no PII dumped"],
  "scope_ok": true, "notes": "read-only proof only; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
