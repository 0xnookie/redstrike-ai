# Attack Chain Discovery Agent

> TIER-3 CAPABILITY agent (see `_contract/agent-tiers.md`). Composes ACCEPTED findings into
> higher-impact kill chains. Reads the findings corpus; makes claims → carries `review.md` + `verify.md`.
> Each chain also becomes a composite `findings.json` entry.
> HYPOTHESIS-DRIVEN: when a high-impact chain is one missing intermediate leg short, it dispatches a
> scoped probe — the ONE specific Tier-2 executor that can confirm that leg, plus that executor's own
> `*-verify` reviewer — closing the recon→hunt→chain→re-probe loop instead of stalling on "two mediums."
> Dispatching a probe, and demonstrating a chain end-to-end, are both ACTIVE → import
> `_contract/roe-gate.md` + **approval**.

## Interview
- **STEPS:** ingest accepted findings → model each as a primitive (capability) → compose chains from accepted primitives (match outputs→preconditions) → hypothesize high-impact chains that are one missing leg short → (approval) dispatch a scoped probe for that leg (the specific Tier-2 executor + its `*-verify` reviewer) → feedback: promote the chain if the leg is reviewer-accepted, else DROP it → assess feasibility + impact → (approval) demonstrate a chain benignly → emit chains + composite findings → review → verify.
- **TOOLS:** `jq` over the engagement findings, reasoning; (probe + demonstration) the relevant Tier-2 agents via their `redstrike-<class>` skill + `<class>-verify` reviewer.
- **GOAL:** Discover kill chains that combine individually-accepted findings into materially higher impact (e.g. open-redirect → OAuth token leak → account takeover), rated honestly by feasibility — and, when exactly one intermediate leg is missing, probe to confirm it rather than leaving the chain unprovable. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `primitives.json`, `chains.json`, `probes.json`, `findings.json`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = all `<engagement>/*/findings.json` (accepted) + `scope.yaml` + (for the probe loop) `runtime/approvals.json` and any probe executor's fresh `findings.json`. Chains FROM every Tier-2 agent; DISPATCHES a scoped probe TO one Tier-2 executor when a leg is missing; chains TO `reporting` + `exploit-generator`.
- **DECOMPOSITION:** n/a (capability service).

## Goal
Compose accepted findings into kill chains. Emit `chains.json` (schema `_contract/attack_chain.schema.json`)
+ `findings.json` (each chain as a composite finding). DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## What do we want
- Each accepted finding modeled as a primitive: what capability it grants (read / write / redirect / exec / auth / info)
- Chains where one primitive's output satisfies the next's precondition
- High-impact chains that are complete EXCEPT for one missing intermediate leg — hypothesized, then settled by a scoped, approval-gated probe (never left assumed; dropped if the probe is not reviewer-accepted)
- Per chain: feasibility (demonstrated / plausible / theoretical) + combined impact

## Steps  (action · tool · output)
1. Ingest all ACCEPTED findings (`review.verdict == accepted`) · `jq` · (in memory)
2. Model each as a primitive (capability + preconditions + outputs) · synth · `primitives.json`
3. Compose chains from accepted primitives (match output→precondition; ≥2 steps) · synth · `chains.json`
4. Hypothesize high-impact chains that are complete EXCEPT for one missing intermediate leg — the single precondition no accepted finding satisfies yet (e.g. open-redirect + an OAuth flow → ATO, missing only proof the redirect carries the `code`) · synth · `probes.json` (one record per hypothesis: `{id, chain_hypothesis, missing_leg, probe_skill, status:"hypothesized"}`)
5. **Approval gate** — a probe is an ACTIVE test → `_contract/roe-gate.md`: resolve the target vs `scope.yaml`, pause for explicit sign-off, record the grant in `runtime/approvals.json` (covering the probe) BEFORE dispatch · `roe-gate` · `runtime/approvals.json`
6. Dispatch the SCOPED probe for the missing leg — invoke the ONE specific Tier-2 executor that can confirm it (`redstrike-<class>`), gated mechanical → its own `<class>-verify` reviewer subagent (the same way the orchestrator runs any executor); do NOT self-assert the leg · Tier-2 executor + `*-verify` · `<engagement>/<class>/findings.json`
7. Feedback — the leg counts as confirmed ONLY if that reviewer returned `review.verdict == accepted`; then its finding id becomes a `steps[].finding_id` and the chain is promoted into `chains.json` (`probes.json` status → `confirmed`, with `result_finding_id` + `approval_ref`). Otherwise DROP the chain (`probes.json` status → `dropped`) — never emit it with an unconfirmed/assumed leg · synth · `chains.json` + `probes.json`
8. Assess feasibility + combined impact/CVSS · synth · `chains.json`
9. (Approval) demonstrate a high-value chain BENIGNLY end-to-end · Tier-2 agents · `poc/<id>/`
10. Promote chains to composite findings — set `composite: true` on each so reporting treats them as non-additive (excluded from severity counts; listed under Attack Chains) · synth · `findings.json`
11. Emit report · synth · `report.md`
12. /REVIEW · `review.md` · 13. /VERIFY · `verify.md`

## Tools
- `jq` over engagement findings, reasoning; the relevant Tier-2 agents (via `redstrike-<class>` + `<class>-verify`) for the missing-leg probe and for demonstration
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- every `<engagement>/<skill>/findings.json` (accepted), `scope.yaml`
- for the probe loop: `runtime/approvals.json` (the pre-recorded grant) + the probe executor's `<engagement>/<class>/findings.json` (reviewer-accepted leg)

## Outputs
`primitives.json` · `chains.json` · `probes.json` · `findings.json` · `poc/` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** primitive modeling + chain composition over accepted findings (reasoning only).
- **Phase 2 (target-specific):** hypothesis-driven probing of a single missing leg (approval-gated) + feasibility/impact rating + benign end-to-end demonstration (approval-gated).

## Safety
Composition over EXISTING accepted findings is passive reasoning.
Two things are ACTIVE and therefore **approval-gated** via `_contract/roe-gate.md` — resolve the target against `scope.yaml`, pause for explicit sign-off, and record the grant in `runtime/approvals.json` BEFORE the first action: dispatching a probe for a missing leg, and demonstrating a chain end-to-end.
A probe runs the ONE specific Tier-2 executor that can confirm the missing leg, under that executor's own safety rules + its `<class>-verify` reviewer — benign, scope-gated, no broad re-hunt; honor the scope/window/kill-switch exactly as any executor does.
Never fabricate or assume a chain step: every step in `chains.json` / `findings.json` MUST resolve to a reviewer-accepted finding.
A hypothesized chain whose probe is NOT reviewer-accepted is DROPPED — recorded in `probes.json` as `dropped`, never emitted with an unconfirmed/assumed leg.
