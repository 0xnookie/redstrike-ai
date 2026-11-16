# BOLA / BFLA — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the BOLA/BFLA gauntlet. Confirmed = an API authz/exposure flaw demonstrated
with two identities. Re-run the cross-identity request.

## BOLA/BFLA false-positive gauntlet (base check #3)
- [ ] **BOLA: cross-owner via two identities.** Account A's token retrieved/modified account B's object
      (both tester-controlled), returning B-specific data — not own/public data.
- [ ] **BFLA: low-priv reached a privileged op.** A low-priv identity successfully invoked an operation
      the role matrix reserves — the op EXECUTED (not 403).
- [ ] **Excessive data (if claimed) real.** The endpoint returned sensitive fields (PII/internal) the
      client doesn't need and only filters client-side — evidenced.
- [ ] **Mass assignment (if claimed) took effect.** The extra privileged field changed server state
      (read-back).
- [ ] **Cross-skill dup (flag, don't merge).** The same bug may also be reported by `idor` (object-level)
      or `privesc` (function-level). You can't see sibling findings, so DON'T drop it — if it looks like the
      same bug, note it in `review.notes` (e.g. "likely dup of an idor/privesc finding on <asset+object>")
      for reporting to merge.
- [ ] **Test accounts; benign/reversible; scope + approval.**

## CVSS integrity
BOLA (cross-user data) → High; BFLA to admin → High/Critical; excessive PII exposure → per sensitivity.
Justify from the demonstrated access.

Run `scripts/cvss.py "<CVSS vector>"` for any **Medium+** finding to compute the base score (do not hand-assert it); the gate recomputes and flags drift.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|blocked|rejected|needs-evidence", "reviewer": "bola-bfla-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["A token GET /api/v2/users/{B}/card returned B's PAN-masked record (B-only); 200 not 403; test accounts"],
  "scope_ok": true, "notes": "test accounts; no real-user data; possible dup of an idor/privesc finding on this object — flagged for reporting to merge" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
