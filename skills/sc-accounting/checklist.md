# Smart-Contract Accounting / Economic-Invariant — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Enumerate
- [ ] value-flows + token standards (erc4626) ingested from web3_context.json + source
- [ ] intended economic invariants modelled; balance/supply/accounting-mutating fns + the state vars each moves listed
- [ ] slither --print function-summary run; echidna/medusa invariant/property fuzz run

## Find invariant breaks
- [ ] accounting desync checked (early-return / partial path updates var A but not B)
- [ ] incomplete reverse path checked (withdraw/cancel/close undoes all of deposit/place/create; partial fill refunds BOTH ETH + ERC20)
- [ ] off-by-one checked (every `A > B` at `A == B`; `<=` vs `<`; `.length - 1`; loop/epoch/deadline bounds)
- [ ] ERC-4626 share math checked (first-depositor/donation inflation, rounding direction, `_decimalsOffset`, totalAssets manipulation)

## Confirm + emit
- [ ] fork PoC: the stated invariant breaks, read back as before/after state, LOCAL FORK only
- [ ] CVSS + $ impact rated; findings.json valid (empty array = ran, invariants hold = PASS)
- [ ] report.md + repro.sh (forge/cast) written
- [ ] /REVIEW SKILL passes · /VERIFY passes (sc-accounting-verify)
