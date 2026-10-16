# Credential Access — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the credential gauntlet. Confirmed = a weak/recoverable credential demonstrated
benignly with the secret redacted. Re-run the benign proof.

## Credential-access false-positive gauntlet (base check #3)
- [ ] **The weakness is real + demonstrated.** A credential was actually recovered (cracked offline /
      guessed within policy) or a store was readable AND the recovered credential was shown to work once —
      not "this hash looks crackable". 
- [ ] **Offline + policy-safe.** Hash cracking was offline; any online guessing stayed within lockout/rate
      policy and did not lock real users (evidenced).
- [ ] **Redacted.** The artifact stores a fingerprint / masked value, NOT a plaintext secret/hash/key.
      Collected hash files were deleted (`cleanup.md`).
- [ ] **Severity matches reach.** Domain/admin or widely-reused credential → High/Critical; a single low-priv
      account → Medium.
- [ ] **Scope + approval.**

## CVSS integrity
Rate from what the credential unlocks (its reuse/reach), not merely that a hash was crackable.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "credential-access-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["a service account hash cracked offline to a dictionary word (stored as fingerprint); authenticated once to confirm; no lockout; hash file deleted"],
  "scope_ok": true, "notes": "secret redacted to fingerprint; offline crack; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
