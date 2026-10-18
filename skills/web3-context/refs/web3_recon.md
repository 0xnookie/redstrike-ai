# Web3 target recon & context — methodology

Build the shared smart-contract context: what's deployed, is the source available, what's the privileged +
value-moving surface, and is the target worth a deep audit. **Read-only**: fetch source, run static-analysis
inventory, make read-only on-chain calls — never a transaction.

## 1. Resolve the in-scope target
From `scope.yaml`: protocol name, chain(s), contract addresses (and/or a provided source repo + commit).
Out-of-scope chain/address = hard stop. Record each address + chain into `contracts.jsonl`.

## 2. Fetch source (or flag unverified)
```
# verified source + ABI + metadata from the chain explorer (read-only API)
cast etherscan-source -c <chain> <address> -d contracts/<address>      # or the explorer's getsourcecode API
cast code <address> --rpc-url <RPC>                                     # bytecode present? (is it deployed)
```
Unverified source is an **audit blind-spot** — record `verified:false`; bytecode-only review (decompile) is
lower-confidence, note it.

## 3. Fingerprint
```
solc-select use <ver> ; crytic-compile contracts/            # compile to the right solc
slither contracts/ --print human-summary,inheritance,function-summary,modifiers
```
Capture: token standards (ERC-20/721/1155/**4626**/2612-permit/777), compiler version, dependency libraries +
**versions** (e.g. OpenZeppelin x.y — pin for known-CVE cross-ref via `cve-intelligence`), LOC.

## 4. Proxy / upgrade pattern
```
cast storage <address> 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url <RPC>  # EIP-1967 impl slot
cast storage <address> 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103 --rpc-url <RPC>  # EIP-1967 admin slot
```
Classify: Transparent / UUPS / Beacon / Diamond (EIP-2535) / minimal-clone (EIP-1167) / none. Record impl +
admin. (Upgradeability bugs → `sc-upgradeability`.)

## 5. Attack-surface inventory
| Capture | How | Routes to |
|---|---|---|
| privileged / value-moving functions (owner/role-gated, mint/withdraw/upgrade) | `slither --print function-summary,modifiers` | sc-access-control / sc-upgradeability |
| external calls + call targets | `slither --print function-summary`; grep `.call{`, `delegatecall`, `safeTransfer` | sc-reentrancy |
| oracle sources + type (Chainlink / spot-AMM / TWAP / Pyth / custom) | grep `latestRoundData`, `slot0`, `getReserves`, `getPriceUnsafe` | sc-oracle-mev |
| accounting / share math | grep `totalSupply`, `totalAssets`, `convertToShares`, `_decimalsOffset` | sc-accounting |
| signature handling | grep `ecrecover`, `ECDSA.recover`, `_nonces`, `DOMAIN_SEPARATOR`, `permit` | sc-signature |
| value flows | deposit/withdraw/mint/redeem/claim/bridge paths | sc-accounting / sc-reentrancy |

## 6. Pre-dive worth-it gate (advisory — record, don't silently drop)
```
# kill signals (any → proceed:false with rationale)
TVL < ~$500K                              → payout floor too low
2+ top-tier audits on a SIMPLE protocol   → picked-over
< ~500 LOC, single linear flow            → minimal surface
# score (illustrative weights)
TVL > $10M (+2) · critical bounty >= $50K (+2) · no audit on THIS version (+2)
  · < 30 days since deploy (+1) · upgradeable (+1) · protocol you know well (+1)
proceed = score >= 6
```
Payout intuition: `min(bounty_cap, severity_% × TVL)`. Record `scoring{tvl,payout_cap,audit_status,score,proceed,rationale}`.

## 7. Emit + route
Consolidate into `web3_context.json` (schema `_contract/web3_context.schema.json`): contracts, surface,
scoring, and `routing[]` (the `sc-*` executors warranted). Hand dependency versions to `cve-intelligence`
(known-vuln library versions). The executors prove findings with a **Foundry fork PoC** — this feeder only
maps and scores.
