# Smart-Contract Upgradeability — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Enumerate
- [ ] proxy pattern + upgrade mechanism ingested from web3_context.json + source
- [ ] init / upgrade / `_authorizeUpgrade` paths + storage layout + their guards listed
- [ ] slither detectors run (unprotected-upgrade / uninitialized-state / suicidal) + slither-check-upgradeability

## Find gaps
- [ ] uninitialized / re-initializable `initialize()` checked (missing `initializer`/`reinitializer` / `_disableInitializers()`)
- [ ] unprotected `upgradeTo`/`upgradeToAndCall`/`_authorizeUpgrade` + impl `selfdestruct`/`delegatecall` takeover-brick checked
- [ ] storage-layout collision / missing `__gap` / EIP-1967 slot misuse / diamond selector clash / unprotected `diamondCut` / attacker `delegatecall` checked

## Confirm + emit
- [ ] fork PoC: non-privileged signer initializes / upgrades / bricks the proxy (ownership / impl swap / brick), LOCAL FORK only
- [ ] CVSS + $ impact rated; findings.json valid (empty array = ran, upgrade paths sound = PASS)
- [ ] report.md + repro.sh (forge/cast) written
- [ ] /REVIEW SKILL passes · /VERIFY passes (sc-upgradeability-verify)
