# Secrets Validation Agent

> ATOMIC single agent (no feeder) — one job: take candidate secrets (mainly from js-analysis) and
> determine which are REAL, LIVE, and IMPACTFUL — filtering entropy noise, placeholders, and revoked keys.
> ACTIVE (validating a secret uses someone's credential) → imports `_contract/roe-gate.md`. Carries
> `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest candidate secrets → classify + dedupe → validate liveness (benign, where authorized) → assess scope/impact → rate → emit → review → verify.
- **TOOLS:** `jq` (ingest `js-analysis/secrets.json`), provider-specific benign validation calls (read-only, minimal), `trufflehog --only-verified` (where applicable); entropy/classifier.
- **GOAL:** Produce a validated secret inventory — each reported secret confirmed real + live (or strong evidence) + scoped for impact — with false positives filtered. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `secret_candidates.json`, `validations.jsonl`, `findings.json`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/secrets.json` (+ other sources), `js-analysis/refs/secret_regexes.yaml`, `scope.yaml`. Chains FROM `js-analysis`; chains TO `reporting` + (CVE/exploit tier-3).
- **DECOMPOSITION:** n/a (atomic).

## Goal
Validate exposed secrets and report the real, live, impactful ones. Emit `findings.json`
(`_contract/finding.schema.json`).
DONE = `checklist.md` all `- [x]` · `review.md` PASS · every finding accepted.

## What do we want
- Candidate secrets classified by type (AWS key, JWT, API token, DB cred, private key…)
- Liveness per candidate (validated active / strong evidence / revoked / placeholder)
- Scope + impact (what the live secret grants)

## Steps  (action · tool · output)
1. Ingest candidates (`js-analysis/secrets.json` + others); dedupe · `jq` · `secret_candidates.json`
2. Classify type + filter obvious noise (example/test/placeholder, low entropy) · classifier · `secret_candidates.json`
3. Validate liveness with a MINIMAL, benign, read-only probe (where authorized) · provider API · `validations.jsonl`
4. Assess scope/impact of each live secret (what it can do) · synth · (into findings)
5. Rate (CVSS) + write finding · synth · `findings.json`
6. Emit report · synth · `report.md`
7. /REVIEW · `review.md` · 8. /VERIFY · `verify.md`

## Tools
- **Ingest/classify:** `jq`, entropy + known-regex (`js-analysis/refs/secret_regexes.yaml`)
- **Validate (benign):** provider-specific read-only call (e.g. AWS `sts get-caller-identity`), `trufflehog --only-verified`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/secrets.json`, `js-analysis/refs/secret_regexes.yaml`
- `scope.yaml`

## Outputs
`secret_candidates.json` · `validations.jsonl` · `findings.json` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** ingest + classify + noise filter.
- **Phase 2 (target-specific):** benign liveness validation + scope/impact + rating.

## Safety
Validating a secret = using someone else's credential. Do the MINIMUM benign, read-only probe to
prove liveness (e.g. identity call), **never** access/exfiltrate data, modify, or pivot. Only where
authorized by `scope.yaml`; some providers log validation. Never print full secrets in artifacts —
store a redacted fingerprint (last 4 + hash). Scope-gate; audit-log.
