# Smart-Contract Oracle / Price Manipulation & MEV (executor)

> Web3 / smart-contract family (siblings: `sc-access-control`, `sc-upgradeability`, `sc-accounting`,
> `sc-reentrancy`, `sc-signature`). Consumes `web3_context.json` `attack_surface.oracles` + `value_flows`.
> Finds price/oracle sources an attacker can move in one transaction (spot-price-as-oracle, stale / unchecked
> Chainlink, no TWAP / deviation guard) and the flash-loan / sandwich / slippage MEV that monetizes them. ACTIVE
> (benign fork PoC) + findings-producing → imports `_contract/roe-gate.md`. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest oracle sources + value flows + source → enumerate every price read + the swap/borrow/liquidation/redeem path that consumes it → find manipulable reads (AMM spot, unchecked/stale Chainlink, single-block price, missing slippage/deadline) → confirm on a local fork (flash-loan → skew the price → drain/mint at the victim → repay, attacker profit before/after) → rate → emit → review → verify.
- **TOOLS:** `slither --print function-summary` (where each price read is consumed), grep the price surface (`latestRoundData`/`slot0`/`getReserves`/`getAmountsOut`/`getPriceUnsafe`), `foundry` (`forge test --fork-url` fork PoC WITH a flash loan at a pinned block), `semgrep` (solidity), manual review; `web3-context/refs/`.
- **GOAL:** Confirm a smart-contract oracle / price-manipulation flaw — an attacker moves a price/oracle source the protocol trusts and extracts value at the victim (typically flash-loan-funded, atomic) — proven on a local fork, never on live chain. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `checks.jsonl`, `findings.json`, `poc/`, `report.md`, `repro.sh`, `logs/`.
- **DATA / RAG:** inputs = `web3_context.json` (`attack_surface.oracles`, `value_flows`, `contracts`, source paths) + `scope.yaml`. `refs/` = `oracle_mev.md`. Chains FROM `web3-context`; chains TO `reporting`. Overlaps: read-only reentrancy that corrupts a price read → `sc-reentrancy`; pure rounding / share-inflation with no manipulated price → `sc-accounting`.
- **DECOMPOSITION:** this IS the oracle / price-manipulation + MEV variant. Missing/incorrect guards → `sc-access-control`; economic-invariant math without a moved price → `sc-accounting`; reentrancy → `sc-reentrancy`.

## Goal
Prove an attacker can manipulate a trusted price/oracle source and monetize it at the victim (drain / mint / mis-redeem / mis-liquidate), or that a swap lacks slippage/deadline protection.
Emit `findings.json` (`_contract/finding.schema.json`). DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## Steps  (action · tool · output)
1. Ingest `oracles` + `value_flows` + source · `jq web3_context.json` · (into checks)
2. Enumerate every price read + the swap/borrow/liquidation/redeem path that consumes it · `slither --print function-summary` + grep · `checks.jsonl`
3. Find manipulable reads: **spot price as oracle** (`getReserves`/`slot0`/`getAmountsOut`/`balanceOf`), **stale/unchecked Chainlink** (`latestRoundData` w/o `updatedAt`/`answeredInRound`/bounds, no L2 sequencer feed), single-block price / no TWAP / no deviation guard, missing `minAmountOut`/`deadline` (sandwich) · manual review + `refs` · `checks.jsonl`
4. Confirm on a LOCAL FORK (pinned block): flash-loan → skew the manipulable price → drain/mint at the victim → repay; assert attacker profit (before/after balances) · `forge test --fork-url` · `poc/<id>/`
5. Rate (CVSS + $ impact) + write finding · synth · `findings.json`
6. Emit report + repro · synth · `report.md`, `repro.sh`
7. /REVIEW · `review.md` · 8. /VERIFY · `verify.md`

## Tools
- `slither --print function-summary` (price-read consumers), grep (`latestRoundData`/`slot0`/`getReserves`/`getAmountsOut`/`getPriceUnsafe`), `foundry` (fork PoC with a flash loan at a pinned block), `semgrep` (solidity), `slither --detect reentrancy-*` for read-only-reentrancy cross-ref, manual review
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `web3_context.json` (`attack_surface.oracles`, `value_flows`, `contracts`, source paths), `scope.yaml`

## Outputs
`checks.jsonl` · `findings.json` · `poc/` · `report.md` · `repro.sh` · `logs/`

## Phases
- **Phase 1 (generic):** static enumeration of price reads + their consumers; grep the oracle/slippage surface.
- **Phase 2 (target-specific):** manipulability analysis + flash-loan fork PoC + before/after profit + impact + rating.

## Safety
Prove findings on a **LOCAL FORK ONLY** (`forge test --fork-url <RPC>` at a pinned block / `anvil --fork-url`) —
**never a live mainnet transaction, never move real funds**; the flash loan, the price skew, and the profit all
happen on the ephemeral fork, which is discarded. High-impact → APPROVAL-GATED. Scope to the authorized contracts
in `scope.yaml`; redact RPC/explorer keys to fingerprints; audit-log. A grep/detector hit alone is NOT a finding —
a fork PoC that shows the manipulation + attacker profit atomically (before/after balances), or an airtight
code-path argument for a view/logic-only case, must demonstrate the manipulable price actually moves value.
