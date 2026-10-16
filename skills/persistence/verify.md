# Persistence — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the persistence gauntlet. Confirmed = a benign, reversible marker proved the
environment ALLOWS undetected persistence via the named mechanism, AND the mechanism was fully removed.
The finding is the missing control, never a planted backdoor.

## Persistence false-positive + safety gauntlet (base check #3)
- [ ] **The gap is real + demonstrated.** A benign marker installed via the named mechanism actually
      re-triggered (survived logoff/reboot/schedule where applicable) — proof the mechanism works here,
      not merely that a location is writable.
- [ ] **Benign marker only.** The payload wrote a harmless timestamped marker and nothing else — NO
      backdoor, shell, C2, credential change, or disabled defense. Anything beyond a marker ⇒ reject.
- [ ] **Fully removed.** `cleanup.md` shows the mechanism was removed and removal was VERIFIED; nothing
      persistent remains. Un-verified removal ⇒ reject + escalate immediately.
- [ ] **Detectability recorded.** Whether monitoring/EDR alerted is noted (that is the control-gap signal).
- [ ] **Exactly one, scoped + approved.** One mechanism, in-scope host, post-ex approval on file.

## CVSS integrity
Rate the monitoring/control gap, not a hypothetical backdoor. Typically Medium–High by what surviving
reboot/credential-change undetected would give an attacker and how invisible it was. Justify from the
re-trigger proof + the detectability note; reject inflation.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "persistence-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["benign marker re-fired after reboot; mechanism removed + removal verified in cleanup.md; EDR did not alert; one mechanism; in scope + approved"],
  "scope_ok": true, "notes": "control/monitoring gap proven benignly; nothing left behind" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
