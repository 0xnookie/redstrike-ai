# JWT Attack — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the JWT gauntlet. Confirmed = the server ACCEPTED a token the attacker forged/
tampered. Re-send the forged token and confirm authed access.

## JWT false-positive gauntlet (base check #3)
- [ ] **Forged token ACCEPTED.** The PoC shows the server accepting a token with a broken/forged
      signature or tampered claims (authed action/data returned) — not a 401. Decoding/tampering alone
      is not a finding; acceptance is.
- [ ] **Specific flaw identified.** `alg:none` accepted / HMAC secret cracked + re-sign / RS256→HS256
      key confusion / `kid`/`jku` injection / unverified claim — the exact flaw is evidenced.
- [ ] **Privilege actually gained.** The tampered claim (e.g. `role:admin`) produced elevated access,
      verified — not just echoed back.
- [ ] **Benign + scope.** Test account; cracking offline; didn't impersonate a real user's data;
      approved.
- [ ] **In scope.**

## CVSS integrity
Signature bypass / privilege forge → High/Critical (auth bypass / account takeover). Justify from the
accepted-token evidence.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "jwt-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["alg:none token (sig stripped) accepted -> GET /me returned admin profile; server 200 not 401; test account"],
  "scope_ok": true, "notes": "offline only; benign privilege on test account; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
