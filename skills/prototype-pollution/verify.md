# Prototype Pollution — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the PP gauntlet. Confirmed = an attacker-controlled key reached `Object.prototype`
(proven on a FRESH object); a gadget/impact claim needs its own benign proof. Re-run the benign payload.

## Prototype-pollution false-positive gauntlet (base check #3)
- [ ] **Pollution actually reached Object.prototype.** The PoC shows a FRESH, unrelated object (`{}` /
      `Object.prototype.<marker>` / a new server response) carrying the injected marker property AFTER the
      payload — not just the payload object having its own property. A reflected `__proto__` string in a
      response is NOT pollution.
- [ ] **The vector is a real sink.** A recursive merge / deep clone / query-string→object / `Object.assign`
      deep path carried the attacker key — identified in `js-analysis` or proven by behaviour, not guessed.
- [ ] **`constructor.prototype` handled.** If `__proto__` was filtered and the `constructor.prototype`
      form worked, that's noted and proven the same way.
- [ ] **Impact is separated from pollution.** Pollution alone (no gadget) is reported at its true (often
      Low/Medium) severity. An XSS/RCE/DoS claim has its OWN benign proof (XSS canary fired / OOB callback /
      single controlled error) AND names the gadget (which polluted property + which sink consumed it).
- [ ] **Benign + hygienic.** A harmless marker key was used; on a server/shared target the global effect
      was acknowledged and not left persistent/destructive.
- [ ] **Scope + approval.**

## CVSS integrity
Pollution-only → Low/Medium. Pollution→XSS → High. Pollution→server RCE → Critical. Pollution→DoS → Medium/High.
Severity MUST match the gadget actually proven, not the theoretical ceiling.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "prototype-pollution-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["after POST {\"__proto__\":{\"ppmarker\":\"x\"}} to the merge endpoint, a fresh object in the next response carried ppmarker; gadget: polluted 'ppmarker' not consumed -> reported Medium (pollution-only); reproduced"],
  "scope_ok": true, "notes": "marker-only; server-side global effect noted, non-persistent key; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
