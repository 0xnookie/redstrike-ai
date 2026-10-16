# Path Traversal / LFI — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the traversal/LFI gauntlet. Confirmed = a file OUTSIDE the intended directory
was read. Re-run the benign payload and confirm the marker content.

## Traversal/LFI false-positive gauntlet (base check #3)
- [ ] **Out-of-directory read.** The PoC returns the real content of a file outside the app's base dir
      (e.g. the host's hostname from `/etc/hostname`) — not an intended file the feature is meant to
      serve, and not attacker-supplied text.
- [ ] **Traversal actually happened.** The `../`/encoding bypass is the reason it escaped the base dir
      (reproducible), not a feature that legitimately serves that path.
- [ ] **LFI-RCE (if claimed) benignly proven.** Any RCE escalation (wrapper/log-poison) is evidenced
      by a benign OOB/marker, approved — else report LFI (file read) at its severity.
- [ ] **Benign + scope.** Non-sensitive marker used; no destructive reads; in scope; approved.

## CVSS integrity
Arbitrary file read → High (`C:H`); LFI-to-RCE confirmed → Critical. Justify from what was read/executed.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "path-traversal-lfi-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["?file=../../../../etc/hostname returned 'web-01' (real host); base dir was /var/www/uploads; reproducible"],
  "scope_ok": true, "notes": "benign marker only; LFI-RCE not attempted (no approval)" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
