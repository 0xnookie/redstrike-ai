# Web3 Context — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Resolve + fetch
- [ ] In-scope contracts + chains resolved from scope.yaml
- [ ] Verified source fetched (or UNVERIFIED flagged per contract — audit blind-spot)
- [ ] Token standards + compiler version + dependency libs/versions fingerprinted

## Surface
- [ ] Proxy/upgrade pattern mapped (Transparent/UUPS/Beacon/Diamond/clone/none + impl + admin)
- [ ] Privileged functions + external calls inventoried
- [ ] Oracles (source + type) + value flows (deposit/withdraw/mint/redeem/claim/bridge) mapped
- [ ] Prior audits + TVL + payout cap collected

## Score + emit
- [ ] Pre-dive worth-it score computed → proceed/true|false with rationale (no silent drop)
- [ ] routing[] set (which sc-* executors the surface warrants)
- [ ] web3_context.json validates against _contract/web3_context.schema.json
- [ ] summary.md
- [ ] /REVIEW SKILL passes
