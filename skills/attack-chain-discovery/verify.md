# Attack Chain Discovery — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.
# Read the referenced findings' review blocks — every step MUST be an ACCEPTED finding.

Run the 7 base checks + the chain gauntlet on each chain in `findings.json`.

## Attack-chain false-positive gauntlet (base check #3)
- [ ] **Every step is an ACCEPTED finding.** Each `steps[].finding_id` resolves to a finding whose
      `review.verdict == accepted`. A chain built on a rejected/tentative finding is invalid → reject.
- [ ] **The composition is coherent.** Step N's output genuinely satisfies step N+1's precondition
      (e.g. the open-redirect actually carries the OAuth `code` the next step needs) — not a
      non-sequitur juxtaposition. Spell out the link.
- [ ] **Feasibility rated honestly.** `demonstrated` requires end-to-end PoC evidence (`poc/<id>/`);
      otherwise `plausible` (each link realistic) or `theoretical`. Don't label a chain `demonstrated`
      without the evidence.
- [ ] **Impact exceeds the parts.** The chain's combined impact is materially higher than any single
      step (that's the point) — rate the chain, not the sum.
- [ ] **Demonstration was benign + approved + in scope** (if `demonstrated`).

## CVSS integrity
Rate the end-to-end impact (often Critical — e.g. ATO). `demonstrated` carries full weight; `plausible`
notes the assumption; `theoretical` is informational. Justify from the chain + evidence.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "attack-chain-discovery-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["steps RS-2026-003 (open-redirect, accepted) + RS-2026-007 (oauth state missing, accepted); redirect carries code to attacker -> ATO; demonstrated end-to-end on test accounts"],
  "scope_ok": true, "notes": "all steps accepted; demonstrated benignly; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
