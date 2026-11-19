# Code Audit — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the code-audit gauntlet. Confirmed = the white-box evidence standard is MET: a concrete
traced reachable source→sink (or missing-authz / broken-invariant) path cited at `file:line` ACROSS the call
chain, PLUS a written exploit/PoC sketch or an executed PoC / fuzz-triggered crash — with calibrated confidence.
Re-read the cited code path yourself; re-run any benign dynamic PoC.

## Code-audit false-positive gauntlet (base check #3)
- [ ] **Traced path, not a grep assertion.** The finding cites the ACTUAL path from a user-controlled source to
      the sink (or the concrete missing-authz / broken-invariant) at `file:line` across the call chain. A bare
      "the sink appears at X" / a `source_context.json` lead restated / a pattern match with NO traced path ⇒
      `rejected` (`rejection_class: false-positive` if disproven by a guard on the path, else `open-proof-gap`).
- [ ] **Sanitizers / guards / auto-escaping accounted for.** Every control on the path (validator, encoder,
      framework auto-escape, authz guard, type coercion) is named and judged — the path reaches the sink
      UNSANITIZED, or the control is shown ineffective/too-late/fail-open per `counterevidence.md`. A control
      that neutralizes the input ⇒ the candidate is `ruled-out`, not a finding.
- [ ] **Evidence standard met.** Both halves present: (a) the traced reachable path AND (b) a PoC/exploit sketch
      an operator could run, or an executed PoC / fuzz-triggered crash. Missing (b) ⇒ `needs-evidence`
      (sketch is producible) or `blocked` (demonstration prevented by env the executor can't change).
- [ ] **No over-claimed runtime proof.** `confidence: confirmed` ONLY when a dynamic proof exists; a
      static-only path is at most `probable` and must state its runtime-guard uncertainty (WAF / runtime guard /
      deploy config a static read cannot see). An over-claimed `confirmed` on a static-only path ⇒ downgrade
      confidence (not severity) and flag; if the finding rests ENTIRELY on an unproven runtime assumption ⇒
      `needs-evidence`.
- [ ] **Chains built from confirmed legs.** Every kill-chain in `chains.jsonl` cites leg finding-ids that each
      exist in `findings.json` and are themselves confirmed (traced + demonstrated). A chain with an
      unconfirmed / padded leg ⇒ reject the chain (the legs may still stand individually).
- [ ] **Benign + scope + approval.** Any dynamic PoC/fuzz-harness run was benign, on an authorized/sandboxed
      instance, and approved; the asset is in scope.

## CVSS integrity
Rate from the DEMONSTRATED path + reachability per `severity-calibration.md`: a traced, reachable injection/RCE
or an object-level authz bypass with a working PoC → High/Critical; a traced path whose exploitation is
precondition-blocked → record `severity` as demonstrated + a `potential_severity`, and set `confidence`
honestly. Reachability inferred-but-not-shown lowers CONFIDENCE, not severity.

Run `scripts/cvss.py "<CVSS vector>"` for any **Medium+** finding to compute the base score (do not hand-assert it); the gate recomputes and flags drift.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|blocked|rejected|needs-evidence", "reviewer": "code-audit-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["traced req->handler->orm at routes/api.py:42 -> models/order.py:88, no ownership check between identities; PoC GET /api/orders/{id} as user B returns user A order; confidence probable (no runtime WAF seen), static path re-read"],
  "scope_ok": true, "notes": "white-box evidence standard met; dynamic PoC on authorized instance; runtime-guard uncertainty stated" }
```
- `accepted` → `status: verified` → reporting. `blocked` → verified WITH a caveat (real, demonstration env-blocked). `rejected`/`needs-evidence` → bounce + re-run. Only `accepted` + `blocked` reach reporting.
