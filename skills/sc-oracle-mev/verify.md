# Smart-Contract Oracle / Price Manipulation & MEV — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the oracle/MEV gauntlet. Confirmed = an attacker manipulates a price/oracle source the
protocol trusts (AMM spot, stale/unchecked feed, no TWAP) and extracts value at the victim — typically
flash-loan-funded and atomic — demonstrated on a LOCAL FORK at a pinned block (no live-chain transaction),
attacker profit read back before/after. Re-run the Foundry fork PoC when feasible.

## Oracle / price-manipulation & MEV false-positive gauntlet (base check #3)
- [ ] **The price source is genuinely manipulable.** It reads an AMM spot (`getReserves`/`slot0`/`getAmountsOut`/
      `balanceOf(pool)`) or a stale/unchecked Chainlink feed (`latestRoundData` with no `updatedAt` freshness,
      no `answeredInRound >= roundId`, no min/max bounds, no L2 sequencer-uptime gate) — NOT a robust multi-block
      TWAP or a correctly-validated feed. If the read is sound, it is not a finding.
- [ ] **Manipulation + profit shown atomically on a fork.** One transaction/bundle moves the price AND extracts
      value; attacker balance up / victim balance down, read back before/after on the fork — not a hypothetical
      "the price could move".
- [ ] **Flash-loan amounts realistic vs pool depth.** The borrow needed to move the price is actually fundable
      (flash-loan source + pool depth at the pinned block); the skew isn't larger than the liquidity can supply.
- [ ] **It's oracle/price (not another class).** Rounding / share-inflation / accounting math with no manipulated
      price → `sc-accounting`; a missing guard an attacker calls directly → `sc-access-control`; a reentrant
      corruption of the read → `sc-reentrancy`. Reclassify, don't accept here.
- [ ] **In scope.** The contract/chain is in `scope.yaml`.
- [ ] **Proven on a fork, benign.** `forge test --fork-url` at a pinned block; flash loan + manipulation + profit
      + repay all on the ephemeral fork; no live mainnet tx; no real funds moved; fork discarded.

## CVSS integrity
Rate by the value the manipulation actually extracts: drain a lending pool / mint against a fake price / empty a
vault via a bad redemption or liquidation rate → Critical; a bounded skew (capped slippage loss, a sandwich skim,
a short-lived mispricing under a deviation cap) → High/Medium. Recompute from the demonstrated before/after profit
+ pool depth; flag inflation (e.g. a feed that actually checks `updatedAt`/bounds, or a TWAP that resists a
single-block move).

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "sc-oracle-mev-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["forge fork PoC @ pinned block: flash-loaned X, skewed the AMM spot getReserves() the vault prices against, redeemed at the bad rate for +Y profit, repaid; no TWAP/deviation guard; before/after balances read back; no live tx"],
  "scope_ok": true, "notes": "local fork only; no real funds moved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
