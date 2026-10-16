# Exposed Surface — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the exposure gauntlet. Confirmed = an unauthenticated request reaches a
**sensitive, unintended** resource, proven by a response-body **signature** (not a bare status code).
Re-fetch the URL and re-match the signature yourself (GET/HEAD only, in scope).

## Exposure false-positive gauntlet (base check #3)
- [ ] **Signature, not status code.** The response BODY matches a known exposure signature
      (`refs/exposure_signatures.md`) — e.g. `/.git/HEAD` → `ref: refs/`, `.env` → `KEY=VALUE` lines, a
      listing titled "Index of /", an `/actuator/env` / `/metrics` body. A bare `200`/`403`/`401` is NOT
      a finding.
- [ ] **Soft-404 / wildcard ruled out.** A random control path (`/<rand>`) does NOT return the same
      body/size/code. Catch-all 200s, SPA fallbacks and WAF interstitials are excluded (auto-calibration /
      a control probe is in the evidence).
- [ ] **Actually sensitive.** The resource leaks source, secrets, data, internal structure, or a
      privileged panel — not an intentionally public asset (`robots.txt`, `.env.example`, a marketing PDF,
      vendor swagger shipped open).
- [ ] **Unauthenticated / unintended.** Reached with no session (or outside intended access). A page the
      app means to serve publicly is not an exposure. Forced-browsing to an **authz-protected** resource
      (needs a role matrix / ≥2 identities) belongs to `privesc`, not here.
- [ ] **De-duped.** Not already reported by `secrets` (the secret value), `security-headers` (a missing
      header), or `privesc` (access control). Live-secret validation was deferred to `secrets`.
- [ ] **Benign + scoped.** GET/HEAD-only proof, no mass dump (single signature read; reconstructability
      noted, not performed), asset ∈ `scope.yaml`, rate honored.

## CVSS integrity
Tie severity to what the signature actually revealed, not the mere existence of a path:
- Source/secrets reconstructable (`/.git` walkable, `.env` with live creds, a `.sql`/backup with data,
  `/actuator/heapdump`) → **High/Critical** (`C:H`; often a chain to RCE / account takeover).
- Internal/debug panel or info leak (`actuator/env`, `phpinfo`, `server-status`, stack traces) → **Medium**.
- Directory listing / low-value metadata (`.DS_Store`, empty listing) → **Low/Info**.
Recompute the vector from the evidence; reject inflation (a `200` on `/.git/` with no walkable objects is
Info, not High).

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "exposed-surface-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["/.git/HEAD body 'ref: refs/heads/'; random control path 404; repo walkable; in scope; not a secrets/privesc dupe"],
  "scope_ok": true, "notes": "signature-confirmed exposure; no bulk dump; secret validation deferred to secrets" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
