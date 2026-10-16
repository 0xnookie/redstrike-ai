# Container Escape — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the escape gauntlet. Confirmed = host-level access achieved from inside the
container, benignly, reproducibly. Re-run the benign proof.

## Container-escape false-positive gauntlet (base check #3)
- [ ] **Host access is real.** The PoC reads a file that exists on the HOST (not the container image) or
      runs in the host namespace (host hostname/mounts/`id` with host context) — not just "we are privileged".
- [ ] **The vector is named + sufficient.** privileged (cgroup `release_agent`/`notify_on_release`),
      mounted `docker.sock` (create a host-mounting container), hostPath mount, `cap_sys_admin`, exposed
      device/`/proc` — the specific misconfig is evidenced.
- [ ] **Benign + cleaned up.** Host proof is a read/`id`; no persistence, no other-tenant impact; any
      container/file created was removed (`cleanup.md`).
- [ ] **Severity.** Full host/root → Critical; limited host read → High.
- [ ] **Scope + approval.**

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "container-escape-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["mounted /var/run/docker.sock -> ran a container with -v /:/host -> read /host/etc/hostname = the NODE hostname (not the container); reproduced; cleanup removed the helper container"],
  "scope_ok": true, "notes": "benign host read; no persistence; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
