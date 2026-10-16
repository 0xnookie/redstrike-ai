# SSTI — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the SSTI gauntlet. Confirmed = a server-side template expression was
EVALUATED (not reflected). Re-run the arithmetic probe and confirm the computed result.

## SSTI false-positive gauntlet (base check #3)
- [ ] **Server-side evaluation, not reflection.** `{{7*7}}` (or engine equivalent) returned `49` /
      engine-computed output / a template error — proving the expression was evaluated, not echoed. A
      literal `{{7*7}}` in the response is NOT SSTI (that's just reflection → maybe XSS).
- [ ] **Engine identified.** The fingerprint (`{{7*'7'}}` behavior etc.) is consistent and recorded.
- [ ] **RCE claim (if any) benignly proven.** Any RCE escalation is evidenced by a BENIGN proof (OOB
      callback / `sleep` delay), not a destructive command — and was approved. Without exec evidence,
      report SSTI (expression eval) at its own severity, not RCE.
- [ ] **In scope.**

## CVSS integrity
SSTI with confirmed RCE → Critical. SSTI with expression eval / data read but a sandbox blocking exec
→ High/Medium per what's readable. Justify from the benign proof actually obtained.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "ssti-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["{{7*7}}->49 and {{7*'7'}}->7777777 (Jinja2); OOB callback from sleep gadget (approved) -> RCE confirmed benignly"],
  "scope_ok": true, "notes": "no destructive command run; OOB proof only" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
