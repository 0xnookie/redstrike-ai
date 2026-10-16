# Windows Privesc — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the Windows-privesc gauntlet. Confirmed = escalation to SYSTEM/admin achieved
BENIGNLY on an in-scope host, cleaned up.

## Windows-privesc false-positive gauntlet (base check #3)
- [ ] **SYSTEM/admin actually achieved.** The PoC shows `whoami` = `nt authority\system` (or a new admin
      context) obtained via the claimed vector — not just that a misconfig exists. The escalation is the proof.
- [ ] **The vector is the cause.** The specific misconfig (unquoted path / weak service ACL /
      AlwaysInstallElevated / SeImpersonate→potato / DLL hijack / token) granted it, reproducibly.
- [ ] **Benign.** Only a benign proof ran (`whoami`, a marker) — no persistence, backdoor, destruction,
      or bulk credential dumping. Anything that risked crashing prod should be feasibility, not run.
- [ ] **Cleaned up.** Anything created (service, binary, registry key, scheduled task) is in `cleanup.md`
      and removed.
- [ ] **Scope + approval.** In-scope host; approved.

## CVSS integrity
Local privesc to SYSTEM → High. Rate by the demonstrated escalation; note the path it enables (domain
compromise if domain-joined → coordinate with `ad-*`). Justify from the SYSTEM proof.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "windows-privesc-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["SeImpersonatePrivilege held; PrintSpoofer -> benign command as SYSTEM; whoami=nt authority\\system; reproduced; no persistence"],
  "scope_ok": true, "notes": "in-scope host; SYSTEM proven with whoami; cleanup.md: none created" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
