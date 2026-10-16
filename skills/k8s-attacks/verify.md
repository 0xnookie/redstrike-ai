# Kubernetes Attacks — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the k8s gauntlet. Confirmed = a real RBAC/exposure path demonstrated benignly.
Re-run the benign proof.

## k8s false-positive gauntlet (base check #3)
- [ ] **The access is real + over-permissioned.** `kubectl auth can-i` (or a direct API/kubelet call)
      SHOWS the dangerous permission AND a benign action succeeded (listed/read what it shouldn't) — not a
      theoretical "the SA might be too broad".
- [ ] **The path is named.** over-permissioned SA (`can-i create pods`/`exec`/`get secrets`), exposed
      kubelet `:10250` (`/run`/`/exec`), unauth API server, or privileged-pod→node — the specific vector + its
      consequence is evidenced.
- [ ] **Benign + cleaned up + redacted.** One read/list proof (host marker if node reached); any test pod
      removed; tokens redacted. No workload disruption, no out-of-scope namespace.
- [ ] **Severity.** cluster-admin / node-root / all-secrets → Critical; namespace-scoped secret/exec → High.
- [ ] **Scope + approval.**

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "k8s-attacks-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["pod SA: kubectl auth can-i create pods -> yes; created a test pod mounting the node fs, read /host/etc/hostname, deleted the pod; token redacted"],
  "scope_ok": true, "notes": "benign; test pod removed; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
