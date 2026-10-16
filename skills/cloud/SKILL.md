# Cloud Exploitation Agent

> ATOMIC agent — cloud-service misconfig + credential abuse (AWS / Azure / GCP) from a web/SSRF foothold or given keys.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval** (cloud account). Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** enumerate cloud footprint (metadata, buckets, exposed services) → reach the metadata service (SSRF → IMDS creds) / use given keys → enumerate identity + permissions → find a privesc / data-exposure path → confirm benignly (own identity, a benign marker) → rate → emit → review → verify.
- **TOOLS:** `aws`/`az`/`gcloud` CLIs, `pacu`, `ScoutSuite`/`prowler` (read-only audit), `refs/cloud_attacks.md`.
- **GOAL:** Confirm a cloud security issue — exposed storage, over-permissioned/escalatable identity, metadata-credential theft via SSRF, or a public sensitive service — with a benign proof (e.g. `sts:GetCallerIdentity`), creds redacted. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `cloud_enum.json`, `cloud_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = an SSRF reaching `169.254.169.254` (from `ssrf-cloud`) OR given keys + `scope.yaml` (account IDs in scope). `refs/` = `cloud_attacks.md`. Chains FROM `ssrf-cloud` / secrets; chains TO `reporting`.
- **DECOMPOSITION:** n/a (atomic; multi-provider in refs).

## Goal
Prove a cloud issue benignly (identity/permission/storage/metadata). Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## What do we want
- The cloud provider + the reachable surface (IMDS via SSRF, public bucket, exposed mgmt service, leaked key)
- The identity it yields + what that identity can do (enumerate, then an escalation/data path)
- A benign proof: `sts:GetCallerIdentity` / `az account show` / token-info, or reading a benign marker object — NOT bulk data

## Steps  (action · tool · output)
1. Enumerate footprint (buckets/subdomains/metadata/exposed services) · recon + refs · `cloud_enum.json`
2. Obtain creds: SSRF → IMDS (IMDSv1 direct; IMDSv2 token dance) OR use given keys · `refs` · `cloud_tests.jsonl`
3. Identity + permission enum (`sts:GetCallerIdentity`, `iam`/`az role`/`gcloud` — read-only) · CLI · `cloud_tests.jsonl`
4. Find a privesc path (IAM passrole/policy, managed identity) OR data exposure (public/over-shared storage) · refs · `cloud_tests.jsonl`
5. Confirm benignly (own identity + one benign action/marker read) · CLI · `poc/<id>/`
6. Rate (CVSS) + write finding (REDACT creds) · synth · `findings.json`
7. Emit report · synth · `report.md` · 8. /REVIEW · `review.md` · 9. /VERIFY · `verify.md`

## Tools
- `aws`/`az`/`gcloud`, `pacu`, `ScoutSuite`/`prowler` (read-only), `refs/cloud_attacks.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- SSRF-to-metadata (from `ssrf-cloud`) or given keys, in-scope account IDs, `scope.yaml`

## Outputs
`cloud_enum.json` · `cloud_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** footprint + obtain identity.
- **Phase 2 (target-specific):** permission/privesc/data path + benign proof + rating (approval-gated).

## Safety
Approval-gated (real cloud account). Read-only enumeration; a benign proof only (own identity / one marker) —
**no** bulk data pull, no resource creation/deletion, no cross-account pivot outside scope. **Redact** all
credentials/tokens in artifacts (store a fingerprint, not the secret). In-scope account IDs only; audit-log.
