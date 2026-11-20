# Attack Chain Discovery — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] All ACCEPTED findings ingested (review.verdict == accepted)

## Compose
- [ ] Each finding modeled as a primitive (capability + preconditions + outputs)
- [ ] Chains composed from accepted primitives (output→precondition match; ≥2 steps)
- [ ] Feasibility assessed (demonstrated / plausible / theoretical)
- [ ] Combined impact / CVSS rated
- [ ] (Approval) a high-value chain demonstrated BENIGNLY end-to-end

## Hypothesis probe (only when a high-impact chain is exactly one missing leg short)
- [ ] High-impact chains with exactly one missing intermediate leg hypothesized (probes.json)
- [ ] (Approval) grant for the probe recorded in runtime/approvals.json BEFORE dispatch (roe-gate; in scope)
- [ ] Scoped probe dispatched — the ONE specific Tier-2 executor (redstrike-<class>) + its <class>-verify reviewer
- [ ] Feedback applied — leg promoted into chains.json ONLY if reviewer-accepted; chain DROPPED otherwise (never emitted with an unconfirmed/assumed leg)

## Emit
- [ ] chains.json validates against _contract/attack_chain.schema.json (every leg resolves to a confirmed finding)
- [ ] probes.json (hypothesis → probe → confirmed/dropped trail; present if any probe ran)
- [ ] findings.json (composite chain findings; schema-valid)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every chain accepted or rejected with reason
