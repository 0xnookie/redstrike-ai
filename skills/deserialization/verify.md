# Insecure Deserialization — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the deserialization gauntlet. Confirmed = the sink deserialized
attacker-controlled data, proven by a BENIGN gadget's OOB callback. Re-run the benign gadget.

## Deserialization false-positive gauntlet (base check #3)
- [ ] **Deserialization proven.** A BENIGN gadget (URLDNS / DNS-only) sent to the sink produced an
      attributable OOB callback from the server — proving attacker-controlled data was deserialized.
      A 500 on malformed input is NOT proof.
- [ ] **Attributable + server-side.** The callback token maps to the sink, from the target egress.
- [ ] **RCE (if claimed) benignly proven + feasible.** Any RCE claim rests on a BENIGN OOB command
      gadget (approved) AND a plausible gadget chain given the libs (`libraries.jsonl`) — not an
      assumption. Without exec evidence, report "deserialization of untrusted data (RCE-feasible)".
- [ ] **Benign only.** No destructive/file-writing/shell gadget was run. Flag any non-benign gadget.
- [ ] **Scope + approval.**

## CVSS integrity
Deserialization with confirmed RCE → Critical. Confirmed deserialization + feasible chain but no exec
proof → High (note feasibility). Justify from the benign evidence; don't assume RCE without it.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "deserialization-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["java ser cookie; URLDNS gadget -> DNS callback token t1 from target egress; commons-collections present -> RCE feasible; no exec gadget run"],
  "scope_ok": true, "notes": "benign URLDNS only; RCE feasibility noted, not executed (approval pending)" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
