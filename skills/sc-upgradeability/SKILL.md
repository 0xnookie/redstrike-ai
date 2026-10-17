# Smart-Contract Upgradeability (executor)

> Web3 / smart-contract family (siblings: `sc-access-control`, `sc-accounting`, `sc-oracle-mev`,
> `sc-reentrancy`, `sc-signature`). Consumes `web3_context.json` `attack_surface.upgrade_mechanism` +
> `contracts[].proxy`. Finds proxy / upgrade flaws (uninitialized or re-initializable init, unprotected
> upgrade, uninitialized-impl takeover/brick, storage-layout collision, diamond selector clash, delegatecall).
> ACTIVE (benign fork PoC) + findings-producing → imports `_contract/roe-gate.md`. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest proxy pattern + upgrade mechanism + source → enumerate init / upgrade / `_authorizeUpgrade` paths + storage layout + their guards → find gaps (missing `initializer`/`reinitializer` / `_disableInitializers()`, unguarded `upgradeTo`/`_authorizeUpgrade`, impl `selfdestruct`/`delegatecall` takeover-brick, storage collision / missing `__gap`, diamond selector clash / unprotected `diamondCut`, delegatecall to attacker target) → confirm on a local fork (non-privileged signer initializes / upgrades / bricks) → rate → emit → review → verify.
- **TOOLS:** `slither` (`--detect unprotected-upgrade,uninitialized-state,suicidal`), `slither-check-upgradeability` (storage-layout / init diff), `foundry` (`forge test --fork-url` / `anvil` fork), `cast storage` (EIP-1967 impl/admin slots), manual proxy/storage review; `web3-context/refs/`.
- **GOAL:** Confirm a smart-contract upgradeability flaw — an unauthorized caller initializes, upgrades, or bricks a proxy/implementation (or a storage-layout collision corrupts state across an upgrade) because the init/upgrade path is unguarded or the layout is unsafe — proven on a local fork, never on live chain. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `checks.jsonl`, `findings.json`, `poc/`, `report.md`, `repro.sh`, `logs/`.
- **DATA / RAG:** inputs = `web3_context.json` (`attack_surface.upgrade_mechanism`, `contracts[].proxy` {pattern, implementation, admin}, source paths) + `scope.yaml`. `refs/` = `upgradeability.md`. Chains FROM `web3-context`; chains TO `reporting`. Overlaps: plain missing-modifier on a business fn → `sc-access-control`; reentrancy via delegatecall → cross-ref.
- **DECOMPOSITION:** this IS the proxy/upgrade variant (init / upgrade / storage / diamond / delegatecall). Plain authz on a non-upgrade fn → `sc-access-control`; economic-invariant math → `sc-accounting`.

## Goal
Prove an unauthorized address can initialize / re-initialize / upgrade / brick a proxy or implementation (or that a
storage-layout collision corrupts state across an upgrade).
Emit `findings.json` (`_contract/finding.schema.json`). DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## Steps  (action · tool · output)
1. Ingest `attack_surface.upgrade_mechanism` + `contracts[].proxy` + source · `jq web3_context.json` · (into checks)
2. Enumerate proxy pattern + init / upgrade / `_authorizeUpgrade` paths + storage layout + their guards · `slither --print function-summary,modifiers` + `slither-check-upgradeability` · `checks.jsonl`
3. Find gaps: uninitialized/re-initializable `initialize` (no `initializer`/`reinitializer`, missing `_disableInitializers()`), unprotected `upgradeTo`/`upgradeToAndCall`/`_authorizeUpgrade`, impl `selfdestruct`/`delegatecall` takeover-brick, storage collision / missing `__gap` / EIP-1967 slot misuse, diamond selector clash / unprotected `diamondCut`, `delegatecall` to attacker target · manual review + `refs` · `checks.jsonl`
4. Confirm on a LOCAL FORK: as a non-privileged signer, call `initialize()` / `upgradeTo` (or brick the impl) → assert ownership taken / impl slot swapped / proxy bricked · `forge test --fork-url` · `poc/<id>/`
5. Rate (CVSS + $ impact) + write finding · synth · `findings.json`
6. Emit report + repro · synth · `report.md`, `repro.sh`
7. /REVIEW · `review.md` · 8. /VERIFY · `verify.md`

## Tools
- `slither` (`--detect unprotected-upgrade,uninitialized-state,suicidal`), `slither-check-upgradeability` (storage-layout / init diff), `foundry` (fork PoC), `cast storage` (EIP-1967 impl/admin slots), manual proxy/storage review
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `web3_context.json` (`attack_surface.upgrade_mechanism`, `contracts[].proxy`, source paths), `scope.yaml`

## Outputs
`checks.jsonl` · `findings.json` · `poc/` · `report.md` · `repro.sh` · `logs/`

## Phases
- **Phase 1 (generic):** static enumeration of proxy pattern + init/upgrade paths + storage layout; detector + upgradeability-check pass.
- **Phase 2 (target-specific):** init/upgrade guard logic + storage-collision + diamond/delegatecall + fork PoC + impact + rating.

## Safety
Prove findings on a **LOCAL FORK ONLY** (`forge test --fork-url <RPC>` / `anvil --fork-url`) — **never a live
mainnet transaction, never move real funds**; the fork is ephemeral and discarded. High-impact →
APPROVAL-GATED. Scope to the authorized contracts in `scope.yaml`; redact RPC/explorer keys to fingerprints;
audit-log. A detector hit alone is NOT a finding — a fork PoC (or an airtight code-path/layout argument for
storage-layout / view-only cases) must demonstrate the unauthorized init/upgrade/brick or the storage collision.
