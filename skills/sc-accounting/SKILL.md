# Smart-Contract Accounting / Economic-Invariant (executor)

> Web3 / smart-contract family (siblings: `sc-access-control`, `sc-upgradeability`, `sc-oracle-mev`,
> `sc-reentrancy`, `sc-signature`). Consumes `web3_context.json` `attack_surface.value_flows` +
> `contracts[].standards` (erc4626). Finds economic-invariant breaks: accounting desync, incomplete code
> paths, off-by-one, ERC-4626 share math. ACTIVE (benign fork PoC) + findings-producing → imports
> `_contract/roe-gate.md`. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest value-flows + token standards + source → model the intended economic invariants + enumerate balance/supply/accounting-mutating fns (which state vars each moves) → find invariant breaks (accounting desync on an early-return / incomplete reverse path / off-by-one boundary / ERC-4626 share math) → confirm on a local fork (the invariant breaks: before/after state) → rate → emit → review → verify.
- **TOOLS:** `slither --print function-summary`, `echidna`/`medusa` (invariant / property fuzzing), `foundry` (`forge test --fork-url` / `anvil` fork), manual function-pair / invariant review; `web3-context/refs/`.
- **GOAL:** Confirm a smart-contract accounting / economic-invariant flaw — a real intended invariant (`totalAssets == Σ balances`, reserves track shares/debt, a forward fn fully reversed) is broken so value can be stolen/minted or the protocol drifts — proven on a local fork, never on live chain. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `checks.jsonl`, `findings.json`, `poc/`, `report.md`, `repro.sh`, `logs/`.
- **DATA / RAG:** inputs = `web3_context.json` (`attack_surface.value_flows`, `contracts[].standards` incl. erc4626, `contracts`, source paths) + `scope.yaml`. `refs/` = `accounting.md`. Chains FROM `web3-context`; chains TO `reporting`. Overlaps: missing guard on the mutating fn → `sc-access-control`; price/oracle-driven mispricing → `sc-oracle-mev`; state desync via a re-entrant call → `sc-reentrancy`.
- **DECOMPOSITION:** this IS the economic-invariant / math variant (desync, incomplete path, off-by-one, share math). Authorization gaps → `sc-access-control`; oracle price manipulation → `sc-oracle-mev`.

## Goal
Prove a real intended economic invariant breaks — reserves/shares/debt drift, a reverse path leaves residual state, a boundary is off by one, or ERC-4626 share math lets a depositor steal/mint value.
Emit `findings.json` (`_contract/finding.schema.json`). DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## Steps  (action · tool · output)
1. Ingest `value_flows` + `standards` (erc4626) + source · `jq web3_context.json` · (into checks)
2. Model the intended invariants + enumerate balance/supply/accounting-mutating fns (which state vars each moves) · `slither --print function-summary` · `checks.jsonl`
3. Find invariant breaks: **accounting desync** (early-return/partial path updates var A not B), **incomplete reverse path** (withdraw/cancel/close doesn't undo all of deposit/place/create; partial fill doesn't refund BOTH ETH + ERC20), **off-by-one** (every `A > B` at `A == B`; `<=` vs `<`; `.length - 1`; loop/epoch/deadline bounds), **ERC-4626 share math** (first-depositor/donation inflation, round DOWN on deposit / UP on withdraw, `_decimalsOffset`, `totalAssets` manipulation) · manual review + `echidna`/`medusa` + `refs` · `checks.jsonl`
4. Confirm on a LOCAL FORK: break the stated invariant — read before/after state (inflate shares as first depositor then steal a later depositor's assets; or show reserves desync after the early-return path) · `forge test --fork-url` · `poc/<id>/`
5. Rate (CVSS + $ impact) + write finding · synth · `findings.json`
6. Emit report + repro · synth · `report.md`, `repro.sh`
7. /REVIEW · `review.md` · 8. /VERIFY · `verify.md`

## Tools
- `slither --print function-summary` (state-var write map per fn), `echidna`/`medusa` (invariant / property fuzzing — state `totalAssets == Σ balances` and let the fuzzer break it), `foundry` (fork PoC), manual function-pair / invariant review
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `web3_context.json` (`attack_surface.value_flows`, `contracts[].standards` incl. erc4626, `contracts`, source paths), `scope.yaml`

## Outputs
`checks.jsonl` · `findings.json` · `poc/` · `report.md` · `repro.sh` · `logs/`

## Phases
- **Phase 1 (generic):** static enumeration of accounting-mutating fns + their state-var writes; invariant modelling; property-fuzz pass.
- **Phase 2 (target-specific):** desync / incomplete-path / off-by-one / share-math analysis + fork PoC + impact + rating.

## Safety
Prove findings on a **LOCAL FORK ONLY** (`forge test --fork-url <RPC>` / `anvil --fork-url`) — **never a live
mainnet transaction, never move real funds**; the fork is ephemeral and discarded. High-impact →
APPROVAL-GATED. Scope to the authorized contracts in `scope.yaml`; redact RPC/explorer keys to fingerprints;
audit-log. A fuzzer counterexample or a math hunch alone is NOT a finding — a fork PoC (or an airtight
code-path argument for a view/pure-math case) must break the stated invariant with before/after state.
