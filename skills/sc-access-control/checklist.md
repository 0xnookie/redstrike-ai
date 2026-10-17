# Smart-Contract Access Control — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Enumerate
- [ ] privileged/value-moving functions ingested from web3_context.json + source
- [ ] externally-reachable state-changing fns + their guards (modifier/require/role) listed
- [ ] slither access-control detectors run (arbitrary-send / suicidal / tx-origin / unprotected-*)

## Find guard gaps
- [ ] missing modifier / unprotected privileged fn checked
- [ ] sibling-function omission checked (one of a set gated, a peer not)
- [ ] tx.origin auth / wrong-or-reusable role / default visibility / missing two-step ownership checked

## Confirm + emit
- [ ] fork PoC: non-privileged signer performs the gated effect (state/asset), LOCAL FORK only
- [ ] CVSS + $ impact rated; findings.json valid (empty array = ran, guards sound = PASS)
- [ ] report.md + repro.sh (forge/cast) written
- [ ] /REVIEW SKILL passes · /VERIFY passes (sc-access-control-verify)
