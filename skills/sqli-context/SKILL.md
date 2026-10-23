# SQLi Context (shared feeder)

> RECON / context feeder for the SQLi family (variants: `sqli-inband`, `sqli-blind`).
> ACTIVE (sends benign fuzz) → honors `_contract/roe-gate.md`. Emits NO findings → `review.md` only.
> Output: `sqli_context.json` (schema `_contract/sqli_context.schema.json`).

## Interview
- **STEPS:** enumerate candidate params → benign-fuzz for SQL-ish anomalies → classify query context → fingerprint DBMS + error visibility + WAF → route to variant → emit → review.
- **TOOLS:** `jq` over `js-analysis`, interceptor, `sqlmap --fingerprint` (detection only), differential probes (`'`, `"`, `)`, `--`, arithmetic); `refs/sqli_payloads.md`.
- **GOAL:** Map injectable points, their query context (string/numeric/identifier/order-by/LIKE), backend DBMS, and error visibility into `sqli_context.json`. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `candidates.json`, `probes.jsonl`, `sqli_context.json`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/out/<site>/findings/{params,endpoints,apis}.jsonl`, `scope.yaml`. `refs/` = `sqli_payloads.md`. Also ingests optional `source-audit/source_context.json` (white-box SQL-sink candidates, if source was audited — merge as higher-confidence leads the executor still PROVES). Chains FROM `js-analysis` (+ `source-audit` when source is in scope); chains TO `sqli-inband|blind`.
- **DECOMPOSITION:** n/a (feeder).

## Goal
Produce the shared SQLi context (injectable points + context + DBMS + error visibility + routing).
DONE = `checklist.md` all `- [x]` · `review.md` PASS (`sqli_context.json` validates against the schema).

## What do we want
- Injectable params (differential response to `'` / arithmetic / boolean)
- Query context per point (string-quoted / numeric / identifier / ORDER BY / LIKE / JSON)
- Backend DBMS + whether errors are visible (→ error/union in-band) + WAF presence

## Steps  (action · tool · output)
1. Enumerate candidate params · `jq`/`grep` js-analysis · `candidates.json`
2. Benign-fuzz each (`'`, `"`, `)`, `--`, `1-0`, `AND 1=1/1=2`) for SQL anomalies · interceptor · `probes.jsonl`
3. Classify query context + detect DBMS (error strings, behavior) · `refs/sqli_payloads.md` + `sqlmap --fingerprint` · `probes.jsonl`
4. Note error visibility + WAF; route each point (`variant_hint`) · synth · (into context)
5. Consolidate + validate vs schema · synth · `sqli_context.json`
6. Emit summary · synth · `summary.md`
7. /REVIEW SKILL · `review.md`

## Tools
- `jq`/`grep` over `js-analysis`, interceptor, `sqlmap` (fingerprint/detection), differential probes; `refs/sqli_payloads.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/out/<site>/findings/`: `params.jsonl`, `endpoints.jsonl`, `apis.jsonl`
- `scope.yaml` (+ `oob.collaborator`), `refs/sqli_payloads.md`

## Outputs
`candidates.json` · `probes.jsonl` · `sqli_context.json` · `summary.md` · `logs/`

## Phases
- **Phase 1 (generic):** enumerate + benign anomaly fuzz.
- **Phase 2 (target-specific):** context classification + DBMS/WAF fingerprint + routing.

## Safety
Detection only here — benign, **SELECT-safe** probes; NEVER stacked/destructive queries
(no `;DROP`, `UPDATE`, `DELETE`); no data dumping (that's the variants, approval-gated, read-only).
Scope-gate; rate-limit; audit-log.
