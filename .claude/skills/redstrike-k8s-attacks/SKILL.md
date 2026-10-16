---
name: redstrike-k8s-attacks
description: Run the Redstrike Kubernetes attack hunt (post-exploitation) — service-account RBAC abuse (auth can-i), exposed kubelet/API/etcd, privileged-pod→node, exposed secrets — confirmed benignly (can-i + one read/list, test pod removed, tokens redacted), then gate and hand off to the k8s-attacks-verify reviewer agent. High-risk, approval-gated.
---

Run the Redstrike **k8s-attacks** methodology (canonical spec: `skills/k8s-attacks/`). Post-exploitation.

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Get approval** + kill switch. Benign proof only (`can-i` + one read/list; a host marker if pod→node); **no** workload disruption, no destructive RBAC/secret changes, no out-of-scope namespace. Remove any test pod (`cleanup.md`); redact tokens. In-scope cluster only.
2. **Execute:** follow `skills/k8s-attacks/SKILL.md` on the pod/cluster foothold; work `skills/k8s-attacks/checklist.md`; use `skills/k8s-attacks/refs/`. Write outputs to `<engagement>/k8s-attacks/`.
3. **Coverage:** copy your filled checklist into `<engagement>/k8s-attacks/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/k8s-attacks --out <engagement>/k8s-attacks` → fix + re-run until exit 0.
5. **Reviewer:** launch the `k8s-attacks-verify` subagent on `<engagement>/k8s-attacks`. Only `accepted` findings go to reporting.
