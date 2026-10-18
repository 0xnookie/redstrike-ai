# Smart-Contract Signature Verification (executor)

> Web3 / smart-contract family (siblings: `sc-access-control`, `sc-upgradeability`, `sc-accounting`,
> `sc-oracle-mev`, `sc-reentrancy`). Consumes `web3_context.json` `contracts[].standards` (erc2612-permit)
> + `attack_surface`. Finds flawed cryptographic signature verification (unchecked `ecrecover`, malleability,
> replay, cross-domain, EIP-2612 permit) that lets a forged/replayed signature authorize an action. ACTIVE
> (benign fork PoC) + findings-producing → imports `_contract/roe-gate.md`. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest signature-verifying functions + source (`ecrecover` / `ECDSA.recover` / `permit` / `_hashTypedDataV4` sinks) → enumerate each verify path + its anti-forgery controls (return-value check / malleability guard / nonce / domain separator / deadline) → find the flaw (unchecked ecrecover / malleable-used-as-key / replayable / cross-domain / permit) → confirm on a local fork with `vm.sign` (craft + replay/forge a signature → the unauthorized effect) → rate → emit → review → verify.
- **TOOLS:** `slither` (signature / ecrecover detectors), `foundry` (`forge test --fork-url` / `anvil` fork, `vm.sign`), `semgrep` (solidity), manual EIP-712 / EIP-2612 review; `web3-context/refs/`.
- **GOAL:** Confirm a smart-contract signature-verification flaw — a forged or replayed signature authorizes an action (double-spend, unauthorized transfer / permit, auth bypass) because the on-chain cryptographic check is missing or wrong — proven on a local fork, never on live chain. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `checks.jsonl`, `findings.json`, `poc/`, `report.md`, `repro.sh`, `logs/`.
- **DATA / RAG:** inputs = `web3_context.json` (`contracts[].standards` incl. erc2612-permit, `attack_surface`, source paths) + `scope.yaml`. `refs/` = `signature.md`. Chains FROM `web3-context`; chains TO `reporting`. Overlaps: missing auth with NO crypto check → `sc-access-control`; permit → approval → accounting drain → cross-ref `sc-accounting`.
- **DECOMPOSITION:** this IS the signature / crypto-verification variant (ecrecover / malleability / replay / domain / permit). Plain missing modifier (no signature involved) → `sc-access-control`; economic-invariant math → `sc-accounting`.

## Goal
Prove a forged or replayed signature authorizes an action (or that a signature check is absent/wrong — unchecked
`ecrecover`, malleability, replay, cross-domain, permit). Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## Steps  (action · tool · output)
1. Ingest signature sinks + source (grep `ecrecover` / `ECDSA.recover` / `permit` / `_hashTypedDataV4`) · `jq web3_context.json` + grep · (into checks)
2. Enumerate each verify path + its anti-forgery controls (return-value `!= address(0)` check / malleability guard / nonce / `DOMAIN_SEPARATOR` binding `chainid`+`address(this)` / deadline) · `slither` + `slither --print function-summary` · `checks.jsonl`
3. Find the flaw: unchecked `ecrecover` (`address(0)`), **signature malleability** (SWC-117, sig used as key), **replay** (missing/poor nonce, SWC-121), **cross-domain replay** (domain separator misses `chainid`/`address(this)`, cached-after-fork), **EIP-2612 permit** (front-run / replay / missing deadline), signed-digest reuse across functions · manual review + `refs` · `checks.jsonl`
4. Confirm on a LOCAL FORK: with `vm.sign` (TEST key), craft a valid signature and REPLAY it (2nd call succeeds) or forge via malleability / `address(0)` → assert the unauthorized state change (double-spend / transfer / permit) occurred · `forge test --fork-url` + `vm.sign` · `poc/<id>/`
5. Rate (CVSS + $ impact) + write finding · synth · `findings.json`
6. Emit report + repro · synth · `report.md`, `repro.sh`
7. /REVIEW · `review.md` · 8. /VERIFY · `verify.md`

## Tools
- `slither` (signature detectors: unchecked `ecrecover` / missing zero-address check / `ECDSA` misuse), `foundry` (fork PoC + `vm.sign` to craft/replay sigs), `semgrep` (solidity), manual EIP-712 / EIP-2612 review
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `web3_context.json` (`contracts[].standards` incl. erc2612-permit, `attack_surface`, source paths), `scope.yaml`

## Outputs
`checks.jsonl` · `findings.json` · `poc/` · `report.md` · `repro.sh` · `logs/`

## Phases
- **Phase 1 (generic):** static enumeration of signature sinks + their anti-forgery controls; detector pass.
- **Phase 2 (target-specific):** malleability / replay / domain / permit logic + `vm.sign` fork PoC + impact + rating.

## Safety
Prove findings on a **LOCAL FORK / local test ONLY** (`forge test --fork-url <RPC>` / `anvil --fork-url`) — craft
and replay/forge signatures with `vm.sign` against the fork; **never a live mainnet transaction, never move real
funds**; the fork is ephemeral and discarded. Use only TEST keys (`vm.sign` / `makeAddrAndKey`); redact any real
private key to a fingerprint. High-impact → APPROVAL-GATED. Scope to the authorized contracts in `scope.yaml`;
redact RPC/explorer keys to fingerprints; audit-log. A detector/grep hit alone is NOT a finding — a fork PoC (or
an airtight code-path argument for view/logic-only cases) must demonstrate the forged/replayed-signature effect.
