# Smart-Contract Oracle / Price Manipulation & MEV — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Enumerate
- [ ] oracle sources + value flows ingested from web3_context.json (attack_surface.oracles / value_flows) + source
- [ ] every price read + the swap/borrow/liquidation/redeem path that consumes it listed
- [ ] price surface grepped (latestRoundData / slot0 / getReserves / getAmountsOut / getPriceUnsafe / balanceOf)

## Find manipulable price / MEV
- [ ] spot-price-as-oracle checked (AMM getReserves/slot0/getAmountsOut or balanceOf(pool) used as a price source)
- [ ] stale/unchecked Chainlink checked (updatedAt freshness / answeredInRound >= roundId / min-max bounds / L2 sequencer feed)
- [ ] missing TWAP / single-block price / no deviation guard, and missing minAmountOut/deadline (sandwich/slippage) checked

## Confirm + emit
- [ ] fork PoC: flash-loan → skew the manipulable price → drain/mint at the victim → repay, attacker profit (before/after), LOCAL FORK only
- [ ] CVSS + $ impact rated; findings.json valid (empty array = ran, price sources robust = PASS)
- [ ] report.md + repro.sh (forge/cast) written
- [ ] /REVIEW SKILL passes · /VERIFY passes (sc-oracle-mev-verify)
