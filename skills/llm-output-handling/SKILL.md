# LLM Output Handling Agent  (OWASP LLM05)

> Variant of the AI/LLM family (siblings: `prompt-injection`, `sensitive-disclosure`, `excessive-agency`).
> Insecure output handling: the model's output flows UNSANITIZED to a downstream sink → XSS / SQLi / SSRF / RCE.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md`. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest output sinks → drive the model to emit a payload for each sink → confirm the DOWNSTREAM sink fires (XSS executes / query injects / fetch happens) → hand the downstream proof to the web agent's gauntlet → rate → emit → review → verify.
- **TOOLS:** interceptor, `chrome-devtools-mcp` (if output renders), OOB, `llm-context/refs/llm_testing_guide.md`.
- **GOAL:** Confirm improper output handling — an LLM-emitted payload executes at a downstream sink (the LLM is the injection vector into a classic web vuln). Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `output_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = `llm_context.json` (`output_sinks`) + `scope.yaml`. `refs/` = `llm-context/refs/`. Chains FROM `llm-context` (+ `prompt-injection` to control the output); chains TO `xss-*`/`sqli-*`/`ssrf-*`/`command-injection` (downstream gauntlet) + `reporting`.
- **DECOMPOSITION:** this IS the LLM05 variant.

## Goal
Prove an LLM-emitted payload executes at a downstream sink. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## What do we want
- Which output sink is unsanitized (HTML render / markdown / DB query / URL fetch / code exec)
- An LLM output that carries a payload the sink executes (make the model emit it)
- Downstream confirmation (the sink actually fired) via the relevant web agent's proof

## Steps  (action · tool · output)
1. Ingest output sinks · `jq llm_context.json` · (into tests)
2. Drive the model to emit a sink-appropriate payload (e.g. `<img src=x onerror=...>` for an HTML sink) · `prompt-injection` + interceptor · `output_tests.jsonl`
3. Confirm the DOWNSTREAM sink fires (XSS exec / query inject / OOB fetch) · `chrome-devtools-mcp`/OOB · `poc/<id>/`
4. Hand the downstream proof to the web agent's gauntlet (xss/sqli/ssrf/cmdi) · cross-ref · (into findings)
5. Rate (CVSS) + write finding · synth · `findings.json`
6. Emit report · synth · `report.md`
7. /REVIEW · `review.md` · 8. /VERIFY · `verify.md`

## Tools
- interceptor, `chrome-devtools-mcp` (rendered output), OOB, `llm-context/refs/llm_testing_guide.md`; downstream agents (`xss-*`/`sqli-*`/`ssrf-*`/`command-injection`)
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `llm_context.json` (`output_sinks`), `scope.yaml`

## Outputs
`output_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** make the model emit sink-appropriate payloads.
- **Phase 2 (target-specific):** downstream sink execution confirmation + rating.

## Safety
Benign downstream payloads (the same benign-proof rules as the web agents: `print()`/OOB for XSS, markers
for SQLi, OOB for SSRF — never destructive). The LLM is just the delivery vector; the downstream agent's
safety rules apply. Scope; rate-limit; audit-log.
