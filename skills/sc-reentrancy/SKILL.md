# Smart-Contract Reentrancy (executor)

> Web3 / smart-contract family (siblings: `sc-access-control`, `sc-upgradeability`, `sc-accounting`,
> `sc-oracle-mev`, `sc-signature`). Consumes `web3_context.json` `attack_surface.external_calls` + `value_flows`.
> Finds external calls / token hooks that return control to the attacker BEFORE a state update, letting them
> re-enter and drain or corrupt. ACTIVE (benign fork PoC) + findings-producing → imports `_contract/roe-gate.md`.
> Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest external calls + value flows + source → enumerate value-moving / state-changing fns that make an external call or invoke a token hook, and where the state write sits relative to the call → find reentrant gaps (CEI violation / missing `nonReentrant` / cross-function / cross-contract / read-only stale view / ERC-777/721/1155 hook) → confirm on a local fork (deploy an attacker contract whose fallback/hook re-enters; before/after state) → rate → emit → review → verify.
- **TOOLS:** `slither` (reentrancy detectors), `foundry` (`forge test --fork-url` / `anvil` fork with an attacker contract), `semgrep` (solidity), manual checks-effects-interactions review; `web3-context/refs/`.
- **GOAL:** Confirm a smart-contract reentrancy flaw — an external call (or controllable hook) hands control to the attacker before the state update completes, so they re-enter and drain funds or corrupt shared state — proven on a local fork via an attacker contract (before/after state), never on live chain. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `checks.jsonl`, `findings.json`, `poc/`, `report.md`, `repro.sh`, `logs/`.
- **DATA / RAG:** inputs = `web3_context.json` (`attack_surface.external_calls`, `value_flows`, `contracts`, source paths) + `scope.yaml`. `refs/` = `reentrancy.md`. Chains FROM `web3-context`; chains TO `reporting`. Overlaps: pure economic-invariant math (no re-entrant call) → `sc-accounting`; stale-price read-only reentrancy borders `sc-oracle-mev` — cross-ref; delegatecall-driven control → `sc-upgradeability`.
- **DECOMPOSITION:** this IS the reentrancy variant (control returns to the attacker before the effect). Economic-invariant math with no re-entrant call → `sc-accounting`; oracle/price manipulation → `sc-oracle-mev`; missing authorization → `sc-access-control`.

## Goal
Prove an attacker contract can re-enter a value-moving / state-changing function before its state is updated (CEI
violation / missing `nonReentrant` / exploitable hook / stale view) and drain funds or corrupt shared state.
Emit `findings.json` (`_contract/finding.schema.json`). DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## Steps  (action · tool · output)
1. Ingest `external_calls` + `value_flows` + source · `jq web3_context.json` · (into checks)
2. Enumerate value-moving / state-changing fns that make an external call or invoke a token hook + where the state write sits relative to the call · `slither --print function-summary` + manual · `checks.jsonl`
3. Find reentrant gaps: external call **before** the effect (CEI violation), missing `nonReentrant`, **cross-function** (re-enter a peer sharing state), **cross-contract** (shared state updated out of order), **read-only** stale `view`, **hook-based** (ERC-777 `tokensReceived`/`tokensToSend`, ERC-721 `onERC721Received`, ERC-1155) · `slither` reentrancy detectors + `refs` · `checks.jsonl`
4. Confirm on a LOCAL FORK: deploy an attacker contract whose fallback/hook re-enters the target → assert the drain (attacker balance up, vault down) or state corruption via before/after reads · `forge test --fork-url` · `poc/<id>/`
5. Rate (CVSS + $ impact) + write finding · synth · `findings.json`
6. Emit report + repro · synth · `report.md`, `repro.sh`
7. /REVIEW · `review.md` · 8. /VERIFY · `verify.md`

## Tools
- `slither` (reentrancy detectors: `reentrancy-eth`, `reentrancy-no-eth`, `reentrancy-benign`, `reentrancy-events`, `reentrancy-unlimited-gas`), `foundry` (fork PoC with an attacker contract), `semgrep` (solidity), manual checks-effects-interactions review
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `web3_context.json` (`attack_surface.external_calls`, `value_flows`, `contracts`, source paths), `scope.yaml`

## Outputs
`checks.jsonl` · `findings.json` · `poc/` · `report.md` · `repro.sh` · `logs/`

## Phases
- **Phase 1 (generic):** static enumeration of external-call sites + state-write ordering; reentrancy detector pass.
- **Phase 2 (target-specific):** cross-function / cross-contract / read-only / hook analysis + attacker-contract fork PoC + impact + rating.

## Safety
Prove findings on a **LOCAL FORK ONLY** (`forge test --fork-url <RPC>` / `anvil --fork-url`) with an **attacker
contract** — **never a live mainnet transaction, never move real funds**; the fork is ephemeral and discarded.
High-impact → APPROVAL-GATED. Scope to the authorized contracts in `scope.yaml`; redact RPC/explorer keys to
fingerprints; audit-log. A detector hit alone is NOT a finding — a fork PoC (an attacker contract that re-enters
and whose drain/corruption is read back before/after, or an airtight code-path argument for a read-only/view case)
must demonstrate the re-entrant effect.
