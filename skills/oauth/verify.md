# OAuth / OIDC — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the OAuth gauntlet. Confirmed = a flow manipulation leaked a `code`/token or
enabled account takeover/linking. Re-run the flow and confirm the leak at the attacker endpoint.

## OAuth false-positive gauntlet (base check #3)
- [ ] **Leak/takeover actually occurred.** The PoC shows a `code`/token arriving at the attacker's
      redirect/OOB host, or a victim account linked/taken over — evidenced (not just a redirect that
      didn't carry the secret).
- [ ] **redirect_uri bypass genuine.** The accepted `redirect_uri` is attacker-controllable (suffix/
      subdomain/path/open-redirect in the allowlist) and the `code`/token followed it. (If it's purely
      an open redirect with no token, that's `open-redirect`, lower severity.)
- [ ] **state/CSRF real.** Missing/replayable `state` actually enabled login-CSRF / account linking,
      demonstrated — not just absent.
- [ ] **id_token/code checks.** Any `aud`/`iss`/signature or code-reuse claim is evidenced by the
      server accepting the manipulated artifact.
- [ ] **Test accounts; token to OOB only; scope + approval.**

## CVSS integrity
Account takeover via OAuth → Critical; token/code leak → High. Justify from the demonstrated leak/takeover.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "oauth-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["redirect_uri=https://attacker.oob.sub.target accepted; auth code delivered to attacker host; exchanged for token on test account"],
  "scope_ok": true, "notes": "test accounts; code captured at OOB only; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
