# Smart-Contract Access Control (executor)

> Web3 / smart-contract family (siblings: `sc-upgradeability`, `sc-accounting`, `sc-oracle-mev`,
> `sc-reentrancy`, `sc-signature`). Consumes `web3_context.json` `attack_surface.privileged_functions`.
> Finds missing/incorrect authorization on state-changing or value-moving functions. ACTIVE (benign
> fork PoC) + findings-producing → imports `_contract/roe-gate.md`. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest privileged functions + source → enumerate externally-reachable state-changing fns + their guards → find guard gaps (missing modifier / sibling omission / tx.origin / wrong role / default visibility) → confirm on a local fork (non-privileged signer performs the gated effect) → rate → emit → review → verify.
- **TOOLS:** `slither` (access-control detectors), `foundry` (`forge test --fork-url` / `anvil` fork), `semgrep` (solidity), manual sibling-function review; `web3-context/refs/`.
- **GOAL:** Confirm a smart-contract access-control flaw — an unauthorized caller performs a privileged / value-moving action because the on-chain authorization check is missing or wrong — proven on a local fork, never on live chain. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `checks.jsonl`, `findings.json`, `poc/`, `report.md`, `repro.sh`, `logs/`.
- **DATA / RAG:** inputs = `web3_context.json` (`privileged_functions`, `contracts`, source paths) + `scope.yaml`. `refs/` = `access_control.md`. Chains FROM `web3-context`; chains TO `reporting`. Overlaps: proxy-init/storage → `sc-upgradeability`; privileged fn reachable via delegatecall → cross-ref.
- **DECOMPOSITION:** this IS the authorization variant (missing/incorrect guards on privileged functions). Upgrade/proxy-init → `sc-upgradeability`; economic-invariant math → `sc-accounting`.

## Goal
Prove an unauthorized address can invoke a privileged/value-moving function (or that a guard is absent/wrong).
Emit `findings.json` (`_contract/finding.schema.json`). DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## Steps  (action · tool · output)
1. Ingest `privileged_functions` + source · `jq web3_context.json` · (into checks)
2. Enumerate externally-reachable state-changing fns + their guards (modifiers/require/role) · `slither --print function-summary,modifiers` · `checks.jsonl`
3. Find guard gaps: missing modifier, **sibling-function omission** (`vote()` gated, `poke()` not), `tx.origin` auth, wrong/again-usable role, default visibility, missing two-step ownership · manual review + `refs` · `checks.jsonl`
4. Confirm on a LOCAL FORK: as a non-privileged signer, call the fn → assert the privileged effect (state/asset) occurred · `forge test --fork-url` · `poc/<id>/`
5. Rate (CVSS + $ impact) + write finding · synth · `findings.json`
6. Emit report + repro · synth · `report.md`, `repro.sh`
7. /REVIEW · `review.md` · 8. /VERIFY · `verify.md`

## Tools
- `slither` (access-control detectors: `arbitrary-send`, `suicidal`, `unprotected-upgrade`, `tx-origin`), `foundry` (fork PoC), `semgrep` (solidity), manual review
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `web3_context.json` (`privileged_functions`, `contracts`, source paths), `scope.yaml`

## Outputs
`checks.jsonl` · `findings.json` · `poc/` · `report.md` · `repro.sh` · `logs/`

## Phases
- **Phase 1 (generic):** static enumeration of state-changing fns + guards; detector pass.
- **Phase 2 (target-specific):** sibling-omission + role logic + fork PoC + impact + rating.

## Safety
Prove findings on a **LOCAL FORK ONLY** (`forge test --fork-url <RPC>` / `anvil --fork-url`) — **never a live
mainnet transaction, never move real funds**; the fork is ephemeral and discarded. High-impact →
APPROVAL-GATED. Scope to the authorized contracts in `scope.yaml`; redact RPC/explorer keys to fingerprints;
audit-log. A detector hit alone is NOT a finding — a fork PoC (or an airtight code-path argument for
view/logic-only cases) must demonstrate the unauthorized effect.
