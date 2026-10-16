# Container Escape Agent

> ATOMIC agent (post-ex) — break out of a container to the host (Docker / runc / containerd).
> ACTIVE, HIGH-RISK, findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** confirm we're in a container → enumerate escape vectors (privileged, mounted docker.sock, host mounts, dangerous caps, exposed /proc, kernel) → escape to the host BENIGNLY (prove host access) → confirm → cleanup → rate → emit → review → verify.
- **TOOLS:** `deepce`, `amicontained`, manual enum, `refs/container_escape.md`.
- **GOAL:** Confirm a container→host escape by gaining host-level access BENIGNLY (read a host marker / `id` on the host), on an in-scope host. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `container_enum.json`, `escape_tests.jsonl`, `findings.json`, `poc/`, `cleanup.md`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = the container foothold (from web RCE / k8s) + `scope.yaml`. `refs/` = `container_escape.md`. Chains FROM web RCE / `k8s-attacks`; chains TO `linux-privesc` (on the host) + `reporting`.
- **DECOMPOSITION:** n/a (atomic).

## Goal
Prove a container escape (benign host access). Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## What do we want
- Confirmation we're containerized + the misconfig that enables escape (privileged / docker.sock / hostPath / cap_sys_admin / exposed device)
- The escape technique for that vector
- A BENIGN host proof (read a marker on the host FS / `id` in the host namespace), cleaned up

## Steps  (action · tool · output)
1. Confirm container + enumerate (`/.dockerenv`, cgroups, caps, mounts, sock) · `amicontained`/manual · `container_enum.json`
2. Identify the escape vector (privileged, docker.sock, host mount, cap_sys_admin, core_pattern, release_agent) · refs · `escape_tests.jsonl`
3. Execute the escape to the host BENIGNLY · `refs/container_escape.md` · `poc/<id>/`
4. Confirm host access (read a benign host marker / host `id`) + record anything created · synth · `cleanup.md`
5. Rate (CVSS) + write finding · synth · `findings.json`
6. Emit report · synth · `report.md` · 7. /REVIEW · `review.md` · 8. /VERIFY · `verify.md`

## Tools
- `deepce`, `amicontained`, manual enum, `refs/container_escape.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- the container foothold (in-scope host), `scope.yaml`

## Outputs
`container_enum.json` · `escape_tests.jsonl` · `findings.json` · `poc/` · `cleanup.md` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** confirm container + enumerate escape vectors.
- **Phase 2 (target-specific):** benign escape + host proof + cleanup + rating (approval-gated).

## Safety
Post-ex, **approval-gated**. Escape BENIGNLY (prove host access with a read/`id`) — **no** persistence on the
host, no destruction, no tampering with other containers/tenants. Prefer the safest vector; avoid kernel
exploits that could crash the node (report feasibility). Revert anything created (`cleanup.md`). In-scope host only.
