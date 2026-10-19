# Cloud-Metadata SSRF Agent

> Variant of the SSRF family (siblings: `ssrf-inband`, `ssrf-blind`). Consumes `ssrf_context.json`
> sinks with `variant_hint: cloud` (or any sink that follows redirects / reaches link-local).
> ACTIVE, HIGH-IMPACT, findings-producing → imports `_contract/roe-gate.md` + **approval** (metadata
> creds are a direct path to cloud account compromise). Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest cloud-capable sinks → target the cloud metadata endpoint (per provider) → handle IMDSv2 / required headers → retrieve role creds/token (redacted) → assess scope of the creds → rate → emit → review → verify.
- **TOOLS:** `curl`/interceptor, `refs/metadata_endpoints.md`; provider identity check (benign).
- **GOAL:** Confirm SSRF reaches the cloud metadata service AND yields sensitive instance credentials/tokens — redacted — proving a path to cloud compromise. Done = checklist `- [x]`, review passes, findings accepted + **approved**.
- **OUTPUT:** `metadata_probes.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `ssrf_context.json` (cloud sinks, `internal_targets`) + `js-analysis/out/<site>/analysis/site-summary.md` (cloud provider / stack) + `scope.yaml`. `refs/` = `metadata_endpoints.md` + the feeder's `ssrf-context/refs/`. Chains FROM `ssrf-context`; chains TO `reporting` + (tier-3 Exploit Generator).
- **DECOMPOSITION:** this IS the cloud-metadata variant.

## Goal
Prove metadata-service reach + credential retrieval via an SSRF sink. Emit `findings.json`
(`_contract/finding.schema.json`). DONE = `checklist.md` `- [x]` · `review.md` PASS · findings accepted.

## What do we want
- Which provider's metadata endpoint is reachable (AWS/GCP/Azure/DO/Alibaba/k8s)
- Whether IMDSv2 token / required header is needed and obtainable via the sink
- Retrieved credentials/token (REDACTED) + the scope they grant

## Steps  (action · tool · output)
1. Ingest cloud-capable sinks + detect provider (`js-analysis/out/<site>/analysis/site-summary.md`) · `jq` · (into probes)
2. Target the provider metadata endpoint via the sink (handle headers / IMDSv2 PUT) · `curl`/interceptor · `metadata_probes.jsonl`
3. Retrieve role name → credentials / token (store REDACTED) · sink · `poc/<id>/`
4. Assess cred scope (what the role/token grants) via a benign identity check · provider API · (into findings)
5. Rate (CVSS) + write finding · synth · `findings.json`
6. Emit report + curl · synth · `report.md`, `curl_commands.sh`
7. /REVIEW · `review.md` · 8. /VERIFY · `verify.md`

## Tools
- `curl`/interceptor, `refs/metadata_endpoints.md`; benign provider identity check (e.g. `sts get-caller-identity`)
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `ssrf_context.json` (cloud sinks), `js-analysis/out/<site>/analysis/site-summary.md`, `scope.yaml`
- `refs/metadata_endpoints.md`

## Outputs
`metadata_probes.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** provider detection + metadata-endpoint reach via the sink.
- **Phase 2 (target-specific):** IMDSv2/header handling + credential retrieval + scope assessment (approval-gated).

## Safety
Metadata creds = direct cloud compromise — **approval-gated**; retrieve creds only to PROVE access,
store them REDACTED (never full), do the MINIMUM benign identity check, **never use the creds to
access/modify/pivot** cloud resources. Scope-gate; audit-log. IMDSv2 (token-required) hardening and
169.254.169.254 blocks are expected — note them in the report as mitigations.
