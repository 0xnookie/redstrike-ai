# Cloud Exploitation — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the cloud gauntlet. Confirmed = real cloud access/exposure proven by a benign API
call, creds redacted. Re-run the benign proof.

## Cloud false-positive gauntlet (base check #3)
- [ ] **Access/exposure is real.** A benign authenticated call succeeded (`sts:GetCallerIdentity`,
      `az account show`, token introspection) OR a listed storage object/metadata response is shown — not a
      theoretical "this bucket might be public".
- [ ] **The path is concrete.** The credential source (SSRF→IMDS v1/v2 token dance, leaked key, public
      storage) and the resulting identity + what it can do are evidenced, not assumed.
- [ ] **Benign + redacted.** One marker/identity proof only — no bulk data, no resource create/delete/pivot;
      every secret is REDACTED to a fingerprint in artifacts.
- [ ] **Severity matches reach.** Admin/privesc identity or sensitive-data exposure → High/Critical;
      limited read identity → Medium.
- [ ] **In scope** (account IDs) + approval.

## CVSS integrity
Rate from the reachable blast radius of the identity/exposure, not merely that IMDS responded.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "cloud-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["SSRF IMDSv2 token->role creds; sts:GetCallerIdentity returned arn ...:role/app (redacted acct); role can read S3 bucket X; no bulk pull; in-scope account"],
  "scope_ok": true, "notes": "creds redacted to fingerprint; benign proof only; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
