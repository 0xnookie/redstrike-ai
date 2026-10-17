# Smart-Contract Signature Verification — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Enumerate
- [ ] signature sinks ingested from web3_context.json + source (ecrecover / ECDSA.recover / permit / _hashTypedDataV4)
- [ ] each verify path + its anti-forgery controls listed (return-value != address(0) / malleability guard / nonce / domain separator / deadline)
- [ ] slither signature detectors run (unchecked ecrecover / missing zero-address check / ECDSA misuse)

## Find the signature flaw
- [ ] unchecked ecrecover (address(0) accepted) / malleability (SWC-117, sig used as uniqueness key) checked
- [ ] replay (missing/poor nonce, SWC-121) / cross-domain replay (DOMAIN_SEPARATOR misses chainid/address(this), cached-after-fork) checked
- [ ] EIP-2612 permit (front-run / replay / missing deadline) / signed-digest reuse across functions checked

## Confirm + emit
- [ ] fork PoC: vm.sign crafts + REPLAYS/forges a signature → the unauthorized effect (double-spend/transfer/permit), LOCAL FORK only
- [ ] CVSS + $ impact rated; findings.json valid (empty array = ran, signature scheme sound = PASS)
- [ ] report.md + repro.sh (forge/cast) written
- [ ] /REVIEW SKILL passes · /VERIFY passes (sc-signature-verify)
