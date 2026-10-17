# Smart-contract oracle / price manipulation & MEV — methodology

An attacker moves a price or oracle source the protocol trusts — within a single transaction, usually funded by a
flash loan — so the victim prices, mints, liquidates, or redeems against the wrong number and bleeds value. Proven
on a **local fork** at a pinned block, never live chain.
Refs: CWE-20 (improper input validation) · CWE-682 (incorrect calculation) · CWE-829 (inclusion of untrusted
functionality) · OWASP Smart Contract Top 10 (Oracle / Price Manipulation).

## The ONE rule: a spot price is not an oracle
Any price you can read AND move inside one transaction is attacker-controlled. AMM reserves (`getReserves()`), a
Uniswap-v3 `slot0` tick, `getAmountsOut()`, or a vault's `token.balanceOf(pool)` all shift the instant someone
swaps or donates into the pool — so pricing against them lets a flash loan set the price. A real oracle resists a
single-block move: a multi-block TWAP, or a Chainlink feed whose freshness / round / bounds you actually check.

## Static enumeration
```bash
slither contracts/ --print function-summary                  # where each price read is consumed
semgrep --config p/smart-contracts contracts/
# grep the price-source surface
grep -rn "getReserves\|slot0\|getAmountsOut\|getAmountsIn\|consult" contracts/   # AMM spot used as a price?
grep -rn "balanceOf(" contracts/                             # balance-as-price / share-price donation vector
grep -rn "latestRoundData\|latestAnswer\|getPriceUnsafe\|getPrice(" contracts/   # feed reads — are they checked?
grep -rn "updatedAt\|answeredInRound\|sequencerUptimeFeed" contracts/            # Chainlink freshness / L2 guard present?
grep -rn "minAmountOut\|amountOutMin\|deadline\|slippage" contracts/             # swap protection present?
slither contracts/ --detect reentrancy-no-eth,reentrancy-benign                  # read-only-reentrancy into a price read → cross-ref sc-reentrancy
```

## Manipulation patterns
| Pattern | Signal | Note |
|---|---|---|
| spot price as oracle | `getReserves`/`slot0`/`getAmountsOut` or `balanceOf(pool)` feeds a price | movable in one tx; the core class |
| unchecked / stale Chainlink | `latestRoundData()` used without `updatedAt` freshness, `answeredInRound >= roundId`, or min/max bounds | stale, or pinned at the aggregator's circuit-breaker floor |
| missing L2 sequencer check | Chainlink read on Arbitrum/Optimism/Base with no `sequencerUptimeFeed` gate | serves a stale price while the sequencer is down |
| no TWAP / single-block price | price taken from one block, no time-weighting or deviation cap | a flash-loan skew sticks for the whole call |
| missing slippage/deadline | swap with no `minAmountOut`/`deadline` | sandwich / MEV-extractable |
| flash-loan amplification | a manipulable price + a pool shallow vs available flash liquidity | borrow → skew → profit → repay, atomic |
| read-only reentrancy into a price read | a view price read during a reentrant callback returns a mid-update value | cross-ref sc-reentrancy |

## Confirm on a fork (benign PoC)
```solidity
// forge test --fork-url $RPC --fork-block-number <N> -vvv   (ephemeral fork; no live tx; no real funds)
function test_flashloan_price_manipulation() public {
    uint256 before = asset.balanceOf(attacker);
    vm.startPrank(attacker);
    uint256 loan = <realistic vs pool depth>;
    flashLender.flashLoan(loan);                       // 1) borrow
    //   inside the callback:
    //   amm.swap(loan, ...);                          // 2) skew the manipulable spot price
    //   victim.redeem(...);  // or liquidate / mint   // 3) interact with the victim at the bad price
    //   amm.swap(backEnough, ...);                    // 4) unwind the skew
    //   repay(loan + fee);                            // 5) repay — all atomic
    vm.stopPrank();
    assertGt(asset.balanceOf(attacker), before);       // attacker profited on the fork
}
```
A price that moves but extracts no value (no attacker profit before/after) is a *candidate*, not a finding
(unless a view/logic-only case carries an airtight code-path argument).

## Kill signals (don't report)
- The price comes from a robust multi-block TWAP, or a Chainlink read that checks `updatedAt`, `answeredInRound`,
  and min/max bounds (and the L2 `sequencerUptimeFeed` where applicable).
- The flash-loan / swap needed to move the price exceeds available liquidity / pool depth — the skew isn't fundable.
- The PoC shows a price change but no value extracted — a mispricing with no monetization.
- It's really accounting/rounding with no manipulated price → `sc-accounting`; a direct unguarded call →
  `sc-access-control`; a reentrant read → `sc-reentrancy`.

## Report
Class · contract/function · oracle source + type · severity · root cause (one line) · vulnerable snippet · $ impact
(profit per attack × feasibility) · fix (the exact robust source — a TWAP / a Chainlink read with freshness + bounds
+ sequencer check / `minAmountOut` + `deadline`) · the Foundry fork PoC with before/after balances. Rate by the
value actually extracted (drain via price manipulation → Critical).
