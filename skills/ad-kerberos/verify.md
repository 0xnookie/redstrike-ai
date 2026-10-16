# AD Kerberos — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the Kerberos gauntlet. Confirmed = a demonstrated Kerberos vector, cracked/abused
on a TEST principal, cleaned up. Guard the "capability, not full compromise" line.

## AD-Kerberos false-positive gauntlet (base check #3)
- [ ] **Roast confirmed by an OFFLINE crack.** A kerberoastable/AS-REP hash was obtained AND cracked
      offline (evidence: the plaintext for a weak test account, or a recovered password) — a hash that
      didn't crack is a weaker finding (exposure, not takeover). No online brute-force.
- [ ] **Delegation path demonstrated.** Unconstrained/constrained/RBCD abuse was shown end-to-end on a
      TEST target (e.g. S4U'd to a test service and got a usable ticket) — not just that the flag exists.
- [ ] **Tickets = capability only.** Any golden/silver ticket was forged for a TEST principal to prove
      capability — NOT used to persist or compromise real Domain Admin. Approved.
- [ ] **Cleaned up.** RBCD attributes, created tickets, and any added objects are in `cleanup.md` and removed.
- [ ] **Scope + approval.** Authorized foothold; in scope; approved.

## CVSS integrity
Kerberoast of a privileged account → High/Critical (path to DA); delegation/ticket abuse → Critical
(domain compromise capability). Justify from what was actually cracked/demonstrated, not the theoretical ceiling.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "ad-kerberos-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["svc_sql kerberoastable; TGS cracked offline (hashcat 13100) -> weak pw; account is local admin on 3 hosts; no persistence; offline only"],
  "scope_ok": true, "notes": "capability demonstrated on test scope; cleanup.md: none created" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
