# Business-logic flaw patterns (step 2–3)
# Not payloads — INVARIANTS to test. Derive the actual tests from THIS app's workflows
# (js-analysis/feature_map.md). Record in abuse_tests.jsonl: {workflow, invariant, test, result, impact}.

## Value / price integrity
- Tamper price/amount/currency in the request (client-trusted price).
- Negative quantity / negative amount → credit instead of debit.
- Integer overflow / rounding (0.001 × huge qty; currency sub-unit truncation).
- Apply a coupon/discount multiple times; stack incompatible discounts.

## Ownership / access (coordinate with access-control/IDOR)
- Act on another user's object by id in a workflow step that skips the ownership check.
- Role-gated step reachable by directly POSTing the later step.

## Workflow / state machine
- Skip a required step (e.g. payment) and jump to confirmation/fulfilment.
- Reorder steps; replay a completed step; resume an abandoned flow with changed values.
- Complete a one-time action twice (double-submit, token reuse).

## Quota / limits / rate
- Exceed a per-user limit via parallel requests or multiple sessions.
- Reset a limit by changing an unkeyed parameter.

## Race conditions / TOCTOU (turbo-intruder, single-packet attack)
- Redeem one gift card / coupon / invite N times concurrently.
- Withdraw/transfer the same balance in parallel (double-spend).
- Simultaneous state transitions that both pass a check made before the mutation.

## Method
For each workflow: write the invariant the server MUST enforce, then craft the minimal request
sequence that violates it, execute on a test account, and confirm the advantaged outcome + impact.
