# Subdomain Takeover — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the takeover gauntlet. Confirmed = a dangling record to a genuinely
claimable resource. Re-resolve the record and re-check the service state.

## Takeover false-positive gauntlet (base check #3)
- [ ] **Record is actually dangling.** The CNAME/A/NS target resolves to a third-party whose resource
      is NOT provisioned (evidence: the unclaimed-state fingerprint). A live, serving target is not a
      takeover.
- [ ] **Fingerprint → claimable, not a generic 404.** The signature matches a KNOWN takeover-able
      service state (e.g. S3 `NoSuchBucket`, GitHub Pages "there isn't a GitHub Pages site here",
      Heroku "no such app"). A generic 404/parked page without a claimable backend is not a finding.
- [ ] **Claimability is real.** Evidence the resource can be registered (claim page / free name /
      open bucket name) — not merely an error page. If the service recently patched silent takeovers,
      note it.
- [ ] **Not already owned by the client / another legit tenant.** Rule out that the target is a valid
      resource the client controls.
- [ ] **In scope** (the subdomain ∈ `scope.yaml`). Any actual claim was authorized.

## CVSS integrity
Full subdomain control is typically High (`S:C` — serves attacker content on a trusted name; cookie
scope, phishing, OAuth). Justify from the confirmed claimable state.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "subdomain-takeover-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["cname -> unclaimed S3; NoSuchBucket fingerprint; bucket name registrable; subdomain in scope"],
  "scope_ok": true, "notes": "claimability documented; no hostile claim performed (not authorized)" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
