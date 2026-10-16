# Crypto Attacks — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Crypto surface identified (encrypted cookie/token/ciphertext param) + samples captured
- [ ] Approval obtained (RoE — token forge / data decrypt) + in-scope target confirmed

## Test (scope-gated, benign, TEST data)
- [ ] Mode fingerprinted (ECB block pattern / CBC / CTR)
- [ ] Padding-oracle signal tested (valid vs invalid padding distinguishable)
- [ ] Weak IV/nonce (reuse/predictable) + weak key/PRNG assessed
- [ ] Malleability tested (CBC/CTR bit-flip, ECB cut-and-paste) where applicable
- [ ] Hash length-extension tested where a keyed Merkle–Damgård hash is used
- [ ] Benign proof produced (decrypt/forge a TEST token, or ECB pattern on test data) — no bulk decrypt
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid; test-token proof referenced, no real user data)
- [ ] poc/ per finding
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
