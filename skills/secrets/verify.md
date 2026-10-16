# Secrets Validation — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.
# Failure modes: false-positive secrets (entropy noise, placeholders) AND over-claiming impact.

Run the 7 base checks + the secrets gauntlet. Confirmed = a REAL, LIVE, IMPACTFUL secret.

## Secrets false-positive gauntlet (base check #3)
- [ ] **Real secret, not noise.** Not an example/test/placeholder (`AKIAIOSFODNN7EXAMPLE`, `xxx`,
      docs sample), not a public/publishable key (publishable Stripe `pk_`, public JWT verification
      key), not a random high-entropy string that isn't a credential.
- [ ] **Live, not revoked.** Validated active via a benign probe (evidence in `validations.jsonl`), or
      strong contextual evidence. A confirmed-revoked/expired key ⇒ Info (exposure noted), not an
      active finding.
- [ ] **Impact scoped honestly.** Rate by what the secret actually grants (AWS admin key → Critical;
      a read-only analytics token → Low). Don't assume max privilege without evidence.
- [ ] **Hygiene.** The artifact stores a REDACTED fingerprint, not the full secret. Validation was
      benign/read-only and in scope (no data accessed/modified).
- [ ] **In scope.**

## CVSS integrity
Match the secret's real power + liveness. Live cloud/admin credential → High/Critical;
unverified-but-likely → cap confidence at `probable`; revoked → Info.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "secrets-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["AKIA... validated via sts get-caller-identity (active, account 1234); not the EXAMPLE key; redacted in artifact"],
  "scope_ok": true, "notes": "read-only identity probe only; no resources touched" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
