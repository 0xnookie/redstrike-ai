# Attack Chain Discovery Agent

> TIER-3 CAPABILITY agent (see `_contract/agent-tiers.md`). Composes ACCEPTED findings into
> higher-impact kill chains. Reads the findings corpus; makes claims → carries `review.md` + `verify.md`.
> Each chain also becomes a composite `findings.json` entry. Demonstrating a chain end-to-end is
> ACTIVE → imports `_contract/roe-gate.md` + **approval**.

## Interview
- **STEPS:** ingest accepted findings → model each as a primitive (capability) → compose chains (match outputs→preconditions) → assess feasibility + impact → (approval) demonstrate a chain benignly → emit chains + composite findings → review → verify.
- **TOOLS:** `jq` over the engagement findings, reasoning; (demonstration) the relevant Tier-2 agents.
- **GOAL:** Discover kill chains that combine individually-accepted findings into materially higher impact (e.g. open-redirect → OAuth token leak → account takeover), rated honestly by feasibility. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `primitives.json`, `chains.json`, `findings.json`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = all `<engagement>/*/findings.json` (accepted) + `scope.yaml`. Chains FROM every Tier-2 agent; chains TO `reporting` + `exploit-generator`.
- **DECOMPOSITION:** n/a (capability service).

## Goal
Compose accepted findings into kill chains. Emit `chains.json` (schema `_contract/attack_chain.schema.json`)
+ `findings.json` (each chain as a composite finding). DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## What do we want
- Each accepted finding modeled as a primitive: what capability it grants (read / write / redirect / exec / auth / info)
- Chains where one primitive's output satisfies the next's precondition
- Per chain: feasibility (demonstrated / plausible / theoretical) + combined impact

## Steps  (action · tool · output)
1. Ingest all ACCEPTED findings (`review.verdict == accepted`) · `jq` · (in memory)
2. Model each as a primitive (capability + preconditions + outputs) · synth · `primitives.json`
3. Compose chains (match output→precondition; ≥2 steps) · synth · `chains.json`
4. Assess feasibility + combined impact/CVSS · synth · `chains.json`
5. (Approval) demonstrate a high-value chain BENIGNLY end-to-end · Tier-2 agents · `poc/<id>/`
6. Promote chains to composite findings · synth · `findings.json`
7. Emit report · synth · `report.md`
8. /REVIEW · `review.md` · 9. /VERIFY · `verify.md`

## Tools
- `jq` over engagement findings, reasoning; the relevant Tier-2 agents for demonstration
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- every `<engagement>/<skill>/findings.json` (accepted), `scope.yaml`

## Outputs
`primitives.json` · `chains.json` · `findings.json` · `poc/` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** primitive modeling + chain composition (reasoning only).
- **Phase 2 (target-specific):** feasibility/impact rating + benign end-to-end demonstration (approval-gated).

## Safety
Composition is reasoning over EXISTING accepted findings (passive). Demonstrating a chain end-to-end
chains real exploits → **approval-gated**, benign, scope-gated, via the Tier-2 agents' own safety
rules. Never fabricate a chain step; every step must reference an accepted finding.
