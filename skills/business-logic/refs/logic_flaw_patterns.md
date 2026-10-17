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

---

## Extended arsenal — currency, rounding & refund arithmetic

- Pay in a weaker / mixed currency the server doesn't re-price; exploit charge-currency ≠ refund-currency.
- Sub-unit truncation: a price with fractional cents floored on charge but rounded up on refund.
- Refund more than paid via partial-refund + rounding drift, or refund after a price drop.
- Tax / fee / shipping recomputed AFTER a discount so the discount applies to the gross, not the net.
- Invariant: order total == Σ(server-priced lines) − validated discounts, in ONE currency, refund ≤ paid.

---

## Extended arsenal — discount / credit / loyalty stacking

- Order coupon + store-credit + gift-card application so the running total crosses below zero (credit out).
- Percentage-on-percentage, or a coupon re-applied after a partial refund of the same order.
- Earn loyalty points / cashback on an order, then cancel/refund it but keep the points.
- Self-referral and signup-bonus farming via disposable emails; invite / promo code reuse past its cap.
- Invariant: each incentive applies once, stays non-negative, and is reversed when its order is reversed.

---

## Extended arsenal — state-machine & verification-gate bypass

- Force-browse straight to a terminal state (`status=paid`, `step=confirm`), skipping the gate before it.
- Skip email / phone / KYC / age verification by POSTing the post-verification step directly.
- Cancel-after-fulfilment or downgrade-then-refund to keep goods/tier while clawing payment back.
- Invariant: a state transition is reachable only from its legal predecessor, server-enforced.

---

## Extended arsenal — replay, idempotency & webhook abuse

- Replay a signed / one-time request with a stale nonce or timestamp the server still accepts.
- Spoof or replay a payment-success / refund webhook (weak or missing signature) to mark an order paid.
- Reuse an idempotency key with a changed body, or omit it, to double an effect.
- Invariant: each economic event is processed once; provider callbacks are authenticated + bound to an order.

---

## Extended arsenal — trust-boundary assumptions (assumed → break)

| Server assumes | Attacker break |
|---|---|
| client-sent price / total is correct | tamper the amount / hidden price field |
| hidden field (`role`, `isAdmin`, `userId`) is immutable | set it in the workflow request (mass-assign) |
| the client only sends legal next-states | POST an out-of-order / later state |
| a signed client token can't be regenerated | re-sign with a discovered / weak key |
| referer / origin proves intent | forge the header |
