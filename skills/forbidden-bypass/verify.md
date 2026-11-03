# Forbidden / 403 Bypass — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the forbidden-bypass gauntlet. Confirmed = a server-enforced 401/403 access
restriction was reached ANYWAY via request manipulation, and the response carried the REAL restricted
content/behaviour. Re-run the bypass against the baseline.

## Forbidden-bypass false-positive gauntlet (base check #3)
- [ ] **The resource was genuinely restricted.** The baseline (plain request) returns 401/403 with a
      deny body — evidenced in `restricted_endpoints.jsonl`. A resource that was already `200` is NOT this
      class (that is `exposed-surface`).
- [ ] **Real access was granted, not a status flip.** The manipulated request returned the actual
      protected content/behaviour — a body-signature match against the success oracle (expected marker /
      known-200 sibling), not merely a `200` status, not a soft-404, not a redirect/200 login page, not an
      empty/stub body. A `200` with the deny/placeholder body is NOT a bypass.
- [ ] **The manipulation is the cause.** The specific axis (path/dot-segment/`..;/`/encoding/case, method
      or override header, trust/forwarding header, protocol) is what flipped denied→granted, reproducibly —
      remove it and access returns to 401/403.
- [ ] **Not a caching/routing artifact.** Confirmed live (not a stale cache hit), and the granted response
      is the restricted resource itself, not a different public resource the manipulation happened to route to.
- [ ] **De-duped.** Distinct from `exposed-surface` (never-restricted resource) and `auth-bypass` (defeated
      an application login/session/2FA step). This is an edge/proxy/app ACL on a path reached via request
      manipulation.
- [ ] **Benign + in scope.** Read-only confirmation (reached, not dumped); benign trust-header values
      (loopback); no brute-force; approved; in scope.

## CVSS integrity
Rate by what the reached resource grants (admin/debug/actuator panel, internal API, sensitive file →
High/Critical; a low-value restricted page → lower). Justify from evidence; if access was proven but the
action behind it was environment-blocked, record `potential_severity`.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "forbidden-bypass-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["baseline GET /admin -> 403 deny body; GET /admin/..;/ -> 200 with admin-panel marker (oracle match); remove ..;/ -> 403 again; distinct from exposed-surface/auth-bypass; read-only; in scope"],
  "scope_ok": true, "notes": "benign loopback header values; no brute-force; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
