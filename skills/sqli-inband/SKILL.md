# In-Band SQLi Agent

> Variant of the SQLi family (sibling: `sqli-blind`). Consumes `sqli_context.json` points with
> `errors_visible: true` / `variant_hint: inband` (error-based + union-based).
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval** (data access). Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest in-band points → break out of query context → confirm via error/union (benign marker e.g. `version()`) → determine column count/types → extract a MINIMAL proof (db name, version, one benign row) → rate → emit → review → verify.
- **TOOLS:** interceptor, `sqli-context/refs/sqli_payloads.md`, `sqlmap --technique=UE --risk=1` (confirm manually).
- **GOAL:** Confirm in-band SQLi (error/union) with a minimal, read-only data-extraction proof. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `extractions.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `sqli_context.json` (inband points) + `scope.yaml`. `refs/` = `sqli-context/refs/`. Chains FROM `sqli-context`; chains TO `reporting`.
- **DECOMPOSITION:** this IS the in-band variant.

## Goal
Prove SQLi by extracting data in-band (error/union) with a benign, read-only proof. Emit `findings.json`
(`_contract/finding.schema.json`). DONE = `checklist.md` `- [x]` · `review.md` PASS · findings accepted.

## Steps  (action · tool · output)
1. Ingest in-band points · `jq sqli_context.json` · (into tests)
2. Break out of query context; confirm error/union with a benign marker (`version()`) · interceptor + refs · `extractions.jsonl`
3. Column count/types (union) · `ORDER BY` / `UNION SELECT NULL..` · `extractions.jsonl`
4. Extract a MINIMAL proof (db name, user, version, one benign row — no PII) · refs · `poc/<id>/`
5. Rate (CVSS) + write finding · synth · `findings.json`
6. Emit report + curl · synth · `report.md`, `curl_commands.sh`
7. /REVIEW · `review.md` · 8. /VERIFY · `verify.md`

## Tools
- interceptor, `sqli-context/refs/sqli_payloads.md`, `sqlmap --technique=UE --risk=1 --batch` (confirm manually)
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `sqli_context.json` (inband points), `scope.yaml`

## Outputs
`extractions.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** context breakout + injection confirmation (benign marker).
- **Phase 2 (target-specific):** union column mapping + minimal read-only extraction + rating (approval-gated).

## Safety
Read-only, SELECT-safe; **no destructive/stacked queries**; extract only a MINIMAL benign proof
(version/db name/one row) — **never dump real PII or tables**; `sqlmap --risk=1` only. Approval-gated;
scope-gate; audit-log.
