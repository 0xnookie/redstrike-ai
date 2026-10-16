---
name: redstrike-crypto-attacks
description: Run the Redstrike crypto-attacks hunt (executor) — padding oracle (CBC decrypt/forge), ECB block-pattern + cut-and-paste, predictable/reused IV/nonce, weak key/PRNG, CBC/CTR bit-flip malleability, and hash length-extension, confirmed benignly by decrypting/forging a TEST token or showing the ECB pattern on test data (JWT crypto → the jwt skill) — then gate and hand off to the crypto-attacks-verify reviewer agent. Approval-gated.
---

Run the Redstrike **crypto-attacks** methodology (canonical spec: `skills/crypto-attacks/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Approval required** (token forging / data decryption); benign + minimal only (a TEST token / one controlled field / an ECB pattern on test data), never bulk decryption of real user data; rate-limit oracle loops; in-scope target only. JWT `alg:none` / algorithm confusion → the `jwt` skill.
2. **Execute:** follow `skills/crypto-attacks/SKILL.md`; capture the crypto surface, fingerprint the mode, test for an oracle/weakness, prove it benignly on TEST data; work `skills/crypto-attacks/checklist.md`; use `skills/crypto-attacks/refs/`. Write outputs to `<engagement>/crypto-attacks/`.
3. **Coverage:** copy your filled checklist into `<engagement>/crypto-attacks/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/crypto-attacks --out <engagement>/crypto-attacks` → fix + re-run until exit 0.
5. **Reviewer:** launch the `crypto-attacks-verify` subagent on `<engagement>/crypto-attacks`. Only `accepted` findings go to reporting.
