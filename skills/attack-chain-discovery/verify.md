# Attack Chain Discovery — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md + _contract/counterevidence.md. SUBAGENT, fresh context. Precondition: review.md PASSED.
# Read the referenced findings' review blocks — every step MUST be an ACCEPTED finding.

Run the 7 base checks + the chain gauntlet on each chain in `findings.json`.

## Attack-chain false-positive gauntlet (base check #3)
- [ ] **Every step is an ACCEPTED finding (the core invariant).** Each `steps[].finding_id` resolves to a
      finding whose `review.verdict == accepted`. A chain built on a rejected/tentative finding — or on an
      assumed / hypothesized leg that was never probe-confirmed — is invalid → reject. There is NO such
      thing as an emitted chain with an unconfirmed leg.
- [ ] **The composition is coherent.** Step N's output genuinely satisfies step N+1's precondition
      (e.g. the open-redirect actually carries the OAuth `code` the next step needs) — not a
      non-sequitur juxtaposition. Spell out the link.
- [ ] **A probe-confirmed leg is a GENUINE reviewer-accepted finding — not self-asserted.** For any step
      whose finding came from a missing-leg probe, resolve its `finding_id` into the probe executor's own
      `<engagement>/<class>/findings.json` and read that finding's `review` block: it must show
      `review.verdict == accepted` AND `review.reviewer == <class>-verify` (the probe class's OWN reviewer).
      Do NOT trust `probes.json`'s self-reported `reviewer_verdict` — re-read the finding. A leg "confirmed"
      only by the chainer, or stamped only by `attack-chain-discovery-verify`, is NOT confirmed → reject.
- [ ] **The probe stayed in-scope + was approval-gated.** `probes.json` + `runtime/approvals.json` must show
      the probe target inside `scope.yaml` and a grant that PRE-DATES the dispatch and covers the probe
      finding id (`_contract/roe-gate.md` §2). No pre-recorded grant, an out-of-scope target, or a post-hoc
      approval ⇒ the promoted chain is an RoE deviation → reject (base check #6).
- [ ] **A dropped hypothesis stays dropped.** Any hypothesized chain whose probe was NOT reviewer-accepted
      must be ABSENT from `chains.json` + `findings.json` — present only as a `dropped` record in
      `probes.json` / the report (a `counterevidence.md` ruled-out / open-proof-gap, never a silently
      emitted chain). A chain reappearing with the unproven leg → reject.
- [ ] **Feasibility rated honestly.** `demonstrated` requires end-to-end PoC evidence (`poc/<id>/`);
      otherwise `plausible` (each link realistic) or `theoretical`. Don't label a chain `demonstrated`
      without the evidence.
- [ ] **A leg that rests on a mitigation/CSP/filter bypass was RE-VERIFIED on the CURRENT channel
      (bypasses decay).** If any step's feasibility depends on a CSP bypass, WAF/filter evasion,
      browser-quirk primitive, or sanitizer (mXSS/markdown/HTML-cleaner) bypass, that leg must have been
      re-demonstrated THIS engagement against the deployed library version + a current browser build — not
      carried over from an earlier run or a general recollection (`cve-intelligence/refs/vendor_status.md`
      §Part-3, ~6-month decay). A stale or un-re-verified bypass leg caps the chain at `plausible` and never
      `demonstrated` → reject any `demonstrated` chain that rests on one.
- [ ] **Impact exceeds the parts.** The chain's combined impact is materially higher than any single
      step (that's the point) — rate the chain, not the sum.
- [ ] **Any probe or demonstration was benign + approved + in scope** (if a leg was probed, or if `demonstrated`).

## CVSS integrity
Rate the end-to-end impact (often Critical — e.g. ATO). `demonstrated` carries full weight; `plausible`
notes the assumption; `theoretical` is informational. Justify from the chain + evidence.

Run `scripts/cvss.py "<CVSS vector>"` for any **Medium+** finding to compute the base score (do not hand-assert it); the gate recomputes and flags drift.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|blocked|rejected|needs-evidence", "reviewer": "attack-chain-discovery-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["chain-004 steps RS-2026-003 (open-redirect, accepted) + RS-2026-012 (oauth code-leak, accepted via oauth-verify — probe for the missing leg, grant g-2 in runtime/approvals.json pre-dates dispatch, target in scope); redirect carries code to attacker -> ATO; demonstrated end-to-end on test accounts"],
  "scope_ok": true, "notes": "all steps accepted (incl. probe leg re-read in oauth/findings.json); probe approval-gated + in scope; demonstrated benignly; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
