# Kubernetes Attacks Agent

> ATOMIC agent (post-ex / infra) — abuse Kubernetes: service-account tokens, exposed API/kubelet, RBAC privesc, privileged pods.
> ACTIVE, HIGH-RISK, findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** enumerate cluster access (SA token, exposed API server/kubelet, RBAC) → `auth can-i` map → abuse an over-permissioned path (exec/create privileged pod → node, read secrets) → confirm benignly → cleanup → rate → emit → review → verify.
- **TOOLS:** `kubectl`, `kube-hunter`/`kubeletctl`, `peirates`, `refs/k8s_attacks.md`.
- **GOAL:** Confirm a Kubernetes security issue — over-permissioned service account, exposed kubelet/API, RBAC privesc to cluster-admin/node, or exposed secrets — benignly. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `k8s_enum.json`, `k8s_tests.jsonl`, `findings.json`, `poc/`, `cleanup.md`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = a pod foothold (SA token at `/var/run/secrets/...`) OR a reachable API/kubelet + `scope.yaml`. `refs/` = `k8s_attacks.md`. Chains FROM web RCE / `container-escape`; chains TO `reporting` + host privesc.
- **DECOMPOSITION:** n/a (atomic).

## Goal
Prove a k8s issue (RBAC/exposure/secret/node) benignly. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## What do we want
- The access we have (SA token + its RBAC, or an unauth-reachable kubelet/API server)
- The over-permissioned/exposed path (`can-i create pods`, `exec`, read secrets, privileged pod → node)
- A benign proof: `kubectl auth can-i` output + one benign action (list a namespace, read a benign configmap) — no destructive change

## Steps  (action · tool · output)
1. Enumerate access (SA token, API server URL, kubelet `:10250`, RBAC) · `kubectl`/`kubeletctl` · `k8s_enum.json`
2. Map permissions (`kubectl auth can-i --list`) · `kubectl` · `k8s_tests.jsonl`
3. Identify a path (over-perm SA, exec, create privileged pod→node, read secrets, exposed kubelet exec) · refs · `k8s_tests.jsonl`
4. Confirm benignly (can-i proof + one benign read/list; if pod→node, read a host marker) · synth · `poc/<id>/`
5. Record + remove anything created (test pod) · synth · `cleanup.md`
6. Rate (CVSS) + write finding (redact tokens) · synth · `findings.json`
7. Emit report · synth · `report.md` · 8. /REVIEW · `review.md` · 9. /VERIFY · `verify.md`

## Tools
- `kubectl`, `kube-hunter`/`kubeletctl`, `peirates`, `refs/k8s_attacks.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- pod SA token / reachable API/kubelet, `scope.yaml`

## Outputs
`k8s_enum.json` · `k8s_tests.jsonl` · `findings.json` · `poc/` · `cleanup.md` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** access + RBAC mapping.
- **Phase 2 (target-specific):** privesc/exposure path + benign proof + cleanup + rating (approval-gated).

## Safety
Post-ex, **approval-gated**. Benign proof only (`can-i` + one read/list; a host marker if pod→node). **No**
workload disruption, no destructive RBAC/secret changes, no other-tenant/namespace access outside scope.
Remove any test pod created (`cleanup.md`). Redact tokens. In-scope cluster only; audit-log.
