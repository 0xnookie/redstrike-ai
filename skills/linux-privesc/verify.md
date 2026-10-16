# Linux Privesc — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the Linux-privesc gauntlet. Confirmed = escalation to root achieved BENIGNLY on an
in-scope host, cleaned up.

## Linux-privesc false-positive gauntlet (base check #3)
- [ ] **Root actually achieved.** The PoC shows `id` = `uid=0(root)` (or equivalent) obtained via the
      claimed vector — not just that a SUID binary / sudo entry exists. The escalation is the proof.
- [ ] **The vector is the cause.** The specific misconfig (SUID+GTFOBins / sudo rule / writable cron /
      capability / group) is what granted root, reproducibly.
- [ ] **Benign.** Only a benign proof ran (`id`, a marker) — no persistence, backdoor, destruction, or
      data theft. A kernel-exploit that risked crashing prod should be reported as feasibility, not run.
- [ ] **Cleaned up.** Anything created (files, cron entries, SUID copies) is in `cleanup.md` and removed.
- [ ] **Scope + approval.** In-scope host; approved.

## CVSS integrity
Local privesc to root → High (`PR:L→`, local). Rate by the demonstrated escalation; note the path it
enables (e.g. toward domain/other hosts). Justify from the root proof.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "linux-privesc-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["sudo -l allowed /usr/bin/find NOPASSWD; GTFOBins find -exec /bin/sh -> id=uid=0(root); reproduced; benign; no persistence"],
  "scope_ok": true, "notes": "in-scope host; root proven with id only; cleanup.md: none created" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
