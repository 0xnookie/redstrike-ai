# Cloud-Metadata SSRF — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the cloud-metadata gauntlet. Confirmed = SSRF reached the metadata service
AND returned sensitive credentials/token. Guard credential hygiene strictly.

## Cloud-metadata false-positive gauntlet (base check #3)
- [ ] **Metadata reached via the SINK, server-side.** The request to `169.254.169.254` / metadata host
      went through the vulnerable sink from the target's egress — not the tester's own network.
- [ ] **Sensitive data actually retrieved.** The PoC shows real instance credentials / token / role
      data (REDACTED in the artifact), not just a 200 from a non-sensitive metadata path. A reachable
      but non-credential path is lower severity.
- [ ] **IMDS version handled honestly.** If IMDSv2 (token-required) is enforced and the sink could NOT
      perform the PUT-token step, metadata is effectively blocked → down-rate / `needs-evidence`. Only
      claim creds if they were genuinely obtained.
- [ ] **Credential hygiene.** Artifacts store a REDACTED fingerprint, not the full secret; the creds
      were NOT used to access/modify cloud resources (only a benign identity check, if any).
- [ ] **Scope + approval.** In scope; approved.

## CVSS integrity
Retrieved instance credentials → Critical (direct cloud account compromise path). Metadata reachable
but no creds (IMDSv2) → Medium/High per what's exposed. Justify from what was actually obtained.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "ssrf-cloud-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["sink reached IMDSv1 169.254.169.254; retrieved role creds (redacted); IMDSv2 not enforced; identity check only"],
  "scope_ok": true, "notes": "creds redacted; not used; recommend IMDSv2 + egress block" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
