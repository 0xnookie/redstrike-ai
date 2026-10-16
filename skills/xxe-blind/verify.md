# Blind XXE — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the blind XXE gauntlet. Confirmed = an attributable OOB callback proving the
parser fetched the attacker's external DTD/entity. No callback ⇒ no finding.

## Blind XXE false-positive gauntlet (base check #3)
- [ ] **Attributable OOB callback from the parser.** The external-DTD/parameter-entity payload caused
      a callback whose token maps to the sink, from the target egress — proving external entity
      resolution. A malformed-XML 500 is NOT proof.
- [ ] **External resolution, server-side.** The fetch of the DTD/entity came from the server, not a
      client or scanner.
- [ ] **File exfil (if claimed) genuine.** Any claimed file read shows the benign file's real content
      arriving over OOB (e.g. the host's hostname), attributable to the payload.
- [ ] **Benign + scope.** Non-sensitive file; no DoS; in scope; approved.

## CVSS integrity
Blind XXE with OOB file exfil → High (`C:H`). External-DTD resolution without file read → Medium/High
(SSRF-ish). Justify from the callback evidence.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "xxe-blind-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["param-entity DTD fetched http://t1.oob/x.dtd (callback token t1, target egress); exfil callback carried hostname 'web-01'"],
  "scope_ok": true, "notes": "benign /etc/hostname only; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
