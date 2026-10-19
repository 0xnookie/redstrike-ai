# NoSQL Injection Agent

> ATOMIC single agent (no feeder) — operator + syntax injection into NoSQL query languages (MongoDB, …).
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval** (data access). Carries `review.md` + `verify.md`.
## Interview
- **STEPS:** ingest params → fingerprint NoSQL backend → operator injection (`$ne`/`$gt`/`$regex`/`$where`) in auth + queries → syntax injection → blind (`$where` sleep / boolean) → confirm (auth bypass / data extraction, benign) → rate → emit → review → verify.
- **TOOLS:** interceptor, `nosqlmap` (confirm manually), `refs/nosql_payloads.md`.
- **GOAL:** Confirm NoSQL injection — operator/syntax injection that bypasses auth or manipulates a query to return unauthorized data — benignly. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `nosql_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/out/<site>/findings/params.jsonl` + `content-discovery` + `js-analysis/out/<site>/analysis/site-summary.md` (Mongo/Couch/etc.) + `scope.yaml`. `refs/` = `nosql_payloads.md`. Chains FROM recon; chains TO `reporting`.
- **DECOMPOSITION:** n/a (atomic).

## Goal
Prove NoSQL injection (auth bypass / query manipulation), benign. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## What do we want
- Injectable params that reach a NoSQL query (JSON body fields + PHP-style array params)
- The vector: operator injection (`$ne`/`$gt`/`$in`/`$regex`/`$where`) or syntax injection
- A benign proof: auth bypass (login without creds) or a controlled boolean/time differential / minimal data extraction

## Steps  (action · tool · output)
1. Ingest params + NoSQL fingerprint · `jq`/`grep` + `site-summary.md` · (into tests)
2. Operator injection in auth: `user[$ne]=x&pass[$ne]=y` / `{"user":{"$ne":null},"pass":{"$ne":null}}` · interceptor · `nosql_tests.jsonl`
3. Operator injection in queries (`$gt`/`$regex` to extract) · refs · `nosql_tests.jsonl`
4. Syntax injection (`'"`\;{}` breakouts) + `$where` JS injection · refs · `nosql_tests.jsonl`
5. Blind: `$where:'sleep(5000)'` time / boolean `$regex` per-char extraction (minimal) · refs · `nosql_tests.jsonl`
6. Confirm (auth bypass / differential) benignly · interceptor · `poc/<id>/`
7. Rate (CVSS) + write finding · synth · `findings.json`
8. Emit report + curl · synth · `report.md`, `curl_commands.sh`
9. /REVIEW · `review.md` · 10. /VERIFY · `verify.md`

## Tools
- interceptor, `nosqlmap` (confirm manually), `refs/nosql_payloads.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/out/<site>/findings/params.jsonl`, `content-discovery`, `js-analysis/out/<site>/analysis/site-summary.md`, `scope.yaml`

## Outputs
`nosql_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** fingerprint + operator-injection auth bypass.
- **Phase 2 (target-specific):** query/`$where`/blind extraction + rating (approval-gated).

## Safety
Read-only, benign: prove auth bypass or a minimal differential/data marker — **no** bulk data extraction,
no `$where` payloads that could hang the DB (keep sleeps short, rate-limited), no destructive operators.
Approval-gated for data access; scope-gate; audit-log.
