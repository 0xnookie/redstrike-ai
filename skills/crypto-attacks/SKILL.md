# Crypto Attacks Agent

> ATOMIC agent — cryptographic implementation/config attacks (padding oracle, ECB patterns, weak IV/nonce/PRNG, malleability, length-extension). JWT alg-confusion → the `jwt` skill.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval** (token forge / data decrypt). Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** identify crypto surface (cookies/tokens/ciphertext params) → fingerprint mode (ECB block pattern, CBC, CTR) → test for an oracle (padding / error / timing) → test weak IV/nonce reuse + weak key/PRNG → test malleability (bit-flipping) + hash length-extension → confirm benignly (decrypt/forge a TEST token, or show the ECB pattern on test data) → rate → emit → review → verify.
- **TOOLS:** python + pycryptodome, PadBuster, hashpump, `refs/crypto_attacks.md`.
- **GOAL:** Confirm a cryptographic weakness — padding oracle (decrypt/forge), ECB pattern leak + cut-and-paste, predictable/reused IV/nonce, weak key/PRNG, CBC/CTR bit-flip malleability, or hash length-extension — with a benign proof on TEST data. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `crypto_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = encrypted tokens/cookies/params + the endpoint that consumes them + `scope.yaml`. `refs/` = `crypto_attacks.md`. Chains FROM recon / `auth-context`; chains TO `reporting`. JWT crypto → defer to `jwt`.
- **DECOMPOSITION:** n/a (atomic; per-attack recipes in refs).

## Goal
Prove a crypto weakness benignly (decrypt/forge a TEST token, or demonstrate an ECB pattern on test data). Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## What do we want
- The crypto surface (encrypted cookie/token/param) + the mode/construction (ECB vs CBC vs CTR, keyed hash)
- The weakness: padding oracle, ECB identical-block pattern + cut-and-paste, predictable/reused IV/nonce, weak key/PRNG, bit-flip malleability, or hash length-extension
- A benign proof: decrypt or FORGE a TEST token via the oracle, flip a benign bit to change a controlled field, or show the repeating-block ECB pattern on test input — NOT bulk decryption of real user data

## Steps  (action · tool · output)
1. Identify the crypto surface + capture samples (cookies/tokens/ciphertext params) · interceptor · `crypto_tests.jsonl`
2. Fingerprint the mode: ECB (identical plaintext blocks → identical ciphertext blocks) / CBC / CTR · refs · `crypto_tests.jsonl`
3. Padding oracle: perturb a CBC block, watch the valid/invalid-padding signal → decrypt/forge · PadBuster/pycryptodome · `crypto_tests.jsonl`
4. Weak IV/nonce (reuse/predictable) + weak key/PRNG (guessable, low entropy) · refs · `crypto_tests.jsonl`
5. Malleability: CBC/CTR bit-flip a controlled plaintext bit; ECB cut-and-paste blocks · pycryptodome · `crypto_tests.jsonl`
6. Hash length-extension (append to a MAC without the key) · hashpump · `crypto_tests.jsonl`
7. Confirm benignly (decrypt/forge a TEST token / show the ECB pattern) · python · `poc/<id>/`
8. Rate (CVSS) + write finding · synth · `findings.json`
9. Emit report · synth · `report.md` · 10. /REVIEW · `review.md` · 11. /VERIFY · `verify.md`

## Tools
- python + pycryptodome, PadBuster, hashpump, `refs/crypto_attacks.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- Encrypted tokens/cookies/params + the consuming endpoint, `scope.yaml` (JWT → the `jwt` skill)

## Outputs
`crypto_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** surface + mode fingerprint + oracle/weakness detection.
- **Phase 2 (target-specific):** benign decrypt/forge/flip proof on TEST data + rating (approval-gated).

## Safety
Benign + minimal: prove the weakness by decrypting/forging a TEST token, flipping ONE controlled field, or
showing the ECB block pattern on test input — **no** bulk decryption of real user data, no forging another
user's live session beyond a single scoped proof. Padding-oracle loops are rate-limited (they can be noisy).
Approval-gated for token forging / data decryption; scope-gate; audit-log; honor the kill switch. JWT
algorithm confusion / `alg:none` is the `jwt` skill's job.
