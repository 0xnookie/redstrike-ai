# AD ADCS — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the ADCS gauntlet. Confirmed = a cert issued via an ESC misconfig authenticated as
a TEST privileged principal, then revoked.

## AD-ADCS false-positive gauntlet (base check #3)
- [ ] **ESC abused end-to-end.** The PoC shows a certificate ISSUED exploiting the specific ESC (e.g. ESC1
      SAN specifying a privileged principal) AND used to AUTHENTICATE (PKINIT → TGT/NT hash) — not just
      that `certipy find` flagged the template.
- [ ] **Correct ESC classification.** The named ESC matches the actual misconfig (template flags / CA
      settings) evidenced by `certipy find`.
- [ ] **Test principal.** The cert impersonated a TEST privileged account to prove the vector — not a real
      DA used to compromise the domain.
- [ ] **Revoked.** The issued certificate is recorded in `cleanup.md` and was revoked.
- [ ] **ESC8 coercion** (if used) was approved + non-disruptive.
- [ ] **Scope + approval.**

## CVSS integrity
ESC1/ESC8 (→ DA) → Critical. Justify from the demonstrated cert-auth; a flagged-but-unexploited template
is a lower (configuration) finding.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "ad-adcs-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["template 'WebServer' ESC1 (ENROLLEE_SUPPLIES_SUBJECT + client-auth); requested cert w/ SAN=test-da; certipy auth -> TGT; cert revoked"],
  "scope_ok": true, "notes": "test principal; cert revoked (cleanup.md); no persistence" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
