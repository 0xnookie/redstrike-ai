# Blind SQLi Agent

> Variant of the SQLi family (sibling: `sqli-inband`). Consumes `sqli_context.json` points with
> `errors_visible: false` / `variant_hint: blind` (boolean + time + OOB).
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest blind points → confirm boolean differential (`1=1` vs `1=2`) → confirm time-based (conditional SLEEP) → OOB where supported → infer a MINIMAL benign fact (version char) → rate → emit → review → verify.
- **TOOLS:** interceptor, `sqli-context/refs/sqli_payloads.md`, `sqlmap --technique=BT --risk=1`, OOB host; timing/response-diff.
- **GOAL:** Confirm blind SQLi via reproducible boolean/time differentials (or OOB), inferring a minimal benign fact. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `inferences.jsonl`, `callbacks.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `sqli_context.json` (blind points) + `scope.yaml` (`oob.collaborator`). `refs/` = `sqli-context/refs/`. Chains FROM `sqli-context`; chains TO `reporting`.
- **DECOMPOSITION:** this IS the blind variant.

## Goal
Prove blind SQLi via boolean/time/OOB, inferring a minimal benign fact. Emit `findings.json`
(`_contract/finding.schema.json`). DONE = `checklist.md` `- [x]` · `review.md` PASS · findings accepted.

## Steps  (action · tool · output)
1. Ingest blind points · `jq sqli_context.json` · (into tests)
2. Boolean differential (`AND 1=1` vs `AND 1=2`) — reproducible · interceptor · `inferences.jsonl`
3. Time-based (conditional SLEEP; baseline vs delayed, repeated) · timing · `inferences.jsonl`
4. OOB (where supported: DNS/HTTP exfil of a marker) · OOB host · `callbacks.jsonl`
5. Infer a MINIMAL benign fact (e.g. first char of version) to prove extraction · refs · `poc/<id>/`
6. Rate (CVSS) + write finding · synth · `findings.json`
7. Emit report + curl · synth · `report.md`, `curl_commands.sh`
8. /REVIEW · `review.md` · 9. /VERIFY · `verify.md`

## Tools
- interceptor, `sqli-context/refs/sqli_payloads.md`, `sqlmap --technique=BT --risk=1`, OOB (`interactsh`); timing/response-diff
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `sqli_context.json` (blind points), `scope.yaml` (`oob.collaborator`)

## Outputs
`inferences.jsonl` · `callbacks.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** boolean/time confirmation (reproducible differentials).
- **Phase 2 (target-specific):** OOB + minimal inferential extraction + rating (approval-gated).

## Safety
Read-only inference; **no destructive/stacked queries** (avoid stacked time payloads unless safe +
approved); keep time payloads short (SLEEP ≤5s) and rate-limited so you don't exhaust DB connections;
infer only a minimal benign fact — no PII. Approval-gated; scope-gate; audit-log.
