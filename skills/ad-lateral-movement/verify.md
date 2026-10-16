# AD Lateral Movement — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the lateral-movement gauntlet. Confirmed = authenticated to another in-scope host
with a recovered credential and ran a BENIGN command. Guard the benign + cleanup limits.

## Lateral-movement false-positive gauntlet (base check #3)
- [ ] **Access actually achieved.** The PoC shows authentication to a DIFFERENT in-scope host with the
      recovered hash/ticket/cred AND a benign command's output (`whoami`/`hostname`) — not just that the
      cred exists.
- [ ] **The cred came from a confirmed finding.** The hash/ticket/password used was recovered by an
      accepted `ad-kerberos`/`ad-acl-abuse`/`ad-adcs` finding (or the authorized foothold) — not fabricated.
- [ ] **In-scope host, benign only.** The target host is in scope; only a benign command ran — no
      destructive action, data theft, persistence, or disruptive coercion.
- [ ] **Cleaned up.** Any exec artifact (service, uploaded file, ticket) is in `cleanup.md` and removed.
- [ ] **Scope + approval.**

## CVSS integrity
Lateral movement extending access (local admin on N hosts, path toward DA) → High/Critical. Justify from
the hosts actually reached + privilege, not the theoretical domain ceiling.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "ad-lateral-movement-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["PtH with svc_sql NT hash (from accepted kerberoast) -> wmiexec to FS01 (in scope) -> whoami = nt authority\\system; benign; no persistence"],
  "scope_ok": true, "notes": "in-scope host; benign command; artifacts removed (cleanup.md)" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
