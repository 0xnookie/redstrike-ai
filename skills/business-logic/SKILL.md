# Business Logic Agent

> ATOMIC single agent (no feeder) — BESPOKE. Not a payload scanner: it models the app's intended
> workflow + invariants and finds where they can be violated for impact (price/quantity tampering,
> race conditions, workflow-step skipping, quota abuse, state-machine jumps).
> ACTIVE + findings-producing → imports `_contract/roe-gate.md`. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** model workflows + invariants → enumerate assumptions/invariants → design targeted abuse tests per invariant → execute → confirm the invariant broke with impact → rate → emit → review → verify.
- **TOOLS:** interceptor (Caido/mitmproxy) to replay/alter flows, turbo-intruder (race conditions), `js-analysis/out/<site>/analysis/site-summary.md` for intended behavior; human-in-the-loop reasoning.
- **GOAL:** Find business-logic flaws — violations of the app's intended invariants that yield real impact (money, access, data, quota) — each reproducible. The tests are DERIVED per app, not from a payload list. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `workflow_model.md`, `invariants.json`, `abuse_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/out/<site>/analysis/site-summary.md` + `findings/{endpoints,params,apis}.jsonl`, `auth.env` (multi-role), `scope.yaml`. `refs/` = `logic_flaw_patterns.md`. Chains FROM `js-analysis`; chains TO `reporting`. Overlaps access-control/IDOR (coordinate).
- **DECOMPOSITION:** n/a (atomic, bespoke).

## Goal
Model the intended workflow, then break its invariants for impact. Emit `findings.json`
(`_contract/finding.schema.json`).
DONE = `checklist.md` all `- [x]` · `review.md` PASS · every finding accepted.

## What do we want
- The app's key workflows (checkout, signup, transfer, upgrade, redemption) and their STATE machines
- The invariants each assumes (price integrity, ownership, ordering, quantity ≥ 0, one-time use, role gates)
- Targeted tests that violate each invariant; confirmed impact when one breaks

## Steps  (action · tool · output)
1. Model workflows + state machines (from site-summary + crawling the flow) · synth · `workflow_model.md`
2. Enumerate invariants/assumptions per workflow · `refs/logic_flaw_patterns.md` · `invariants.json`
3. Design abuse tests per invariant (tamper, reorder, replay, race, skip step, negative/overflow) · synth · (into tests)
4. Execute abuse tests (interceptor / turbo-intruder for races) · tools · `abuse_tests.jsonl`
5. Confirm the invariant broke WITH impact (money/access/data) · synth · `poc/<id>/`
6. Rate (CVSS, business impact) + write finding · synth · `findings.json`
7. Emit report · synth · `report.md`
8. /REVIEW · `review.md` · 9. /VERIFY · `verify.md`

## Tools
- **Model/execute:** interceptor (Caido / mitmproxy), turbo-intruder (race/TOCTOU), multi-role `auth.env`
- **Intended behavior:** `js-analysis/out/<site>/analysis/site-summary.md`, `findings/apis.jsonl`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/out/<site>/`: `analysis/site-summary.md`, `findings/{endpoints,params,apis}.jsonl`
- `auth.env` (multiple roles/accounts), `scope.yaml`, `refs/logic_flaw_patterns.md`

## Outputs
`workflow_model.md` · `invariants.json` · `abuse_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** model workflows + invariants (understand intended behavior).
- **Phase 2 (target-specific):** per-invariant abuse tests + impact confirmation + rating.

## Safety
Abuse tests touch real workflows (orders, payments, quotas) — use **test accounts**; keep changes
reversible; never complete real purchases or move real funds; race tests can create duplicate state,
so clean up. Scope-gate; approval for anything touching payment/production state; audit-log.
