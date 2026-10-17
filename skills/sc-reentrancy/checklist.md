# Smart-Contract Reentrancy — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Enumerate
- [ ] external calls + value flows ingested from web3_context.json + source
- [ ] value-moving / state-changing fns making an external call or invoking a token hook listed, with the state-write position vs the call
- [ ] slither reentrancy detectors run (reentrancy-eth / -no-eth / -benign / -events / -unlimited-gas)

## Find reentrant paths
- [ ] classic single-function CEI violation checked (external call before the state update, no nonReentrant)
- [ ] cross-function + cross-contract shared-state reentrancy checked
- [ ] read-only reentrancy (stale view) + hook-based (ERC-777 tokensReceived/tokensToSend / ERC-721 onERC721Received / ERC-1155) checked

## Confirm + emit
- [ ] fork PoC: attacker contract re-enters via fallback/hook; before/after state shows drain or corruption, LOCAL FORK only
- [ ] CVSS + $ impact rated; findings.json valid (empty array = ran, CEI/guards sound = PASS)
- [ ] report.md + repro.sh (forge/cast) written
- [ ] /REVIEW SKILL passes · /VERIFY passes (sc-reentrancy-verify)
