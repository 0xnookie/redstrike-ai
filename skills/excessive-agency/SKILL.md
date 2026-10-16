# Excessive Agency Agent  (OWASP LLM06)

> Variant of the AI/LLM family (siblings: `prompt-injection`, `sensitive-disclosure`, `llm-output-handling`).
> Abuses the LLM's TOOLS/agency: tool-parameter injection, SSRF via tools, tool chaining.
> ACTIVE, can cause real actions, findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest tools → enumerate tool params/capabilities → inject into tool args (SQL/shell/path/SSRF) → SSRF via browsing/API tools (OOB) → tool chaining (injection → action in another tool) → confirm unauthorized action (benign/OOB) → rate → emit → review → verify.
- **TOOLS:** interceptor, OOB (`interactsh`), `llm-context/refs/llm_testing_guide.md`; hand downstream injection to the web vuln agents.
- **GOAL:** Confirm excessive agency — the LLM can be driven to perform an unauthorized action via its tools (SSRF, injected tool-arg, chained action) — proven benignly. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `agency_tests.jsonl`, `callbacks.jsonl`, `findings.json`, `poc/`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = `llm_context.json` (`tools`) + `scope.yaml` (`oob.collaborator`). `refs/` = `llm-context/refs/`. Chains FROM `llm-context` (+ `prompt-injection` as the driver); chains TO `reporting` + `ssrf-*`/`sqli-*`/`command-injection` (downstream).
- **DECOMPOSITION:** this IS the LLM06 variant.

## Goal
Prove unauthorized action via LLM tools, benignly. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## What do we want
- The tools/functions the LLM can call + their params + capability
- A driven, unauthorized action: SSRF (OOB from a browsing/API tool), an injected tool-arg reaching a
  backend sink, or a chain (indirect injection → tool action)
- Benign proof (OOB callback / a benign effect), not real damage

## Steps  (action · tool · output)
1. Ingest tools + capabilities · `jq llm_context.json` · (into tests)
2. Enumerate tool params (what args the LLM will pass) · interceptor · `agency_tests.jsonl`
3. SSRF via tool: drive the LLM to fetch an OOB/internal URL · interceptor + OOB · `callbacks.jsonl`
4. Tool-arg injection: pass SQL/shell/path into a tool arg (benign markers) · refs · `agency_tests.jsonl`
5. Tool chaining: indirect injection → action in another tool (benign) · refs · `agency_tests.jsonl`
6. Confirm the unauthorized action (OOB / benign effect) · synth · `poc/<id>/`
7. Rate (CVSS) + write finding · synth · `findings.json`
8. Emit report · synth · `report.md`
9. /REVIEW · `review.md` · 10. /VERIFY · `verify.md`

## Tools
- interceptor, OOB (`interactsh-client`), `llm-context/refs/llm_testing_guide.md`; hand downstream sinks to `ssrf-*`/`sqli-*`/`command-injection`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `llm_context.json` (`tools`), `scope.yaml` (`oob.collaborator`)

## Outputs
`agency_tests.jsonl` · `callbacks.jsonl` · `findings.json` · `poc/` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** tool enumeration + SSRF-via-tool.
- **Phase 2 (target-specific):** tool-arg injection + chaining + benign-action confirmation + rating (approval-gated).

## Safety
The LLM performs REAL actions via tools — **approval-gated**; confirm with BENIGN effects only (OOB
callback, a no-op/marker action) — **never** destructive, no real emails/payments/data changes. SSRF
via tools stays in scope (cloud-metadata reach → hand to `ssrf-cloud`). Kill switch; scope; audit-log.
