# Crypto Attacks — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the crypto gauntlet. Confirmed = a cryptographic weakness is proven by a working
benign primitive (decrypt/forge a TEST token, a controlled bit-flip, or a shown ECB pattern). Re-run the proof.

## Crypto false-positive gauntlet (base check #3)
- [ ] **The primitive actually works.** The PoC decrypts or FORGES a test token the server accepts, flips a
      controlled plaintext field, or shows identical ciphertext blocks for identical plaintext (ECB) — a
      concrete transformation, not "the cookie looks like base64 so it might be weak".
- [ ] **The weakness is the named one.** Padding oracle (a distinguishable valid/invalid-padding signal),
      IV/nonce reuse (same IV/nonce observed across messages), weak key/PRNG (predictability shown), or
      length-extension (extended MAC accepted) — correctly attributed, not guessed.
- [ ] **Benign + minimal.** One TEST token / one controlled field / a pattern on test data — NO bulk
      decryption of real users, no forging a real victim's live session beyond a single scoped proof.
- [ ] **Oracle loop controlled.** Any padding-oracle / per-byte loop is rate-limited and reproducible, not a
      flaky timing read.
- [ ] **Not a JWT finding.** JWT `alg:none` / key-confusion belongs to `jwt` — rejected/redirected here.
- [ ] **Scope + approval.**

## CVSS integrity
Forging an authentication/session token or decrypting sensitive data → High/Critical; a malleability/ECB
pattern with limited controlled impact → Medium. Rate from the demonstrated primitive, not the mere presence
of a weak mode.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "crypto-attacks-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["CBC padding oracle on the session cookie: valid vs invalid padding distinguishable; decrypted a TEST token and forged role=guest->role=tester, server accepted; single scoped proof, no bulk decrypt"],
  "scope_ok": true, "notes": "benign forge on a test account only; padding loop rate-limited; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
