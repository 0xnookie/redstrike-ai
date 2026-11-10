# LLM Context (shared feeder)

> RECON / context feeder for the AI/LLM family (variants: `prompt-injection`, `sensitive-disclosure`,
> `excessive-agency`, `llm-output-handling`). Maps an LLM-integrated app per the OWASP LLM Top 10 (2025).
> Lightly active (benign probes) → honors `_contract/roe-gate.md`. Emits NO findings → `review.md` only.
> Output: `llm_context.json` (schema `_contract/llm_context.schema.json`).

## Interview
- **STEPS:** **verify it's actually generative-LLM-backed (gate — else hand off, don't route)** → fingerprint the model → map the chat/inference API → discover LLM endpoints → classify guardrails → map the LLM's tools/agency → map data sources (RAG/system-prompt/memory) → map output sinks → route → emit → review.
- **TOOLS:** interceptor (chat API), `garak`/`PyRIT` (recon modes), endpoint fuzzing (`ffuf`), benign probes.
- **GOAL:** Map the LLM app's surface — model, API, guardrails, tools (agency), data sources, and output sinks — into `llm_context.json`, so the variants fan out. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `api_map.json`, `surface_probes.jsonl`, `llm_context.json`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/out/<site>/findings/{endpoints,apis}.jsonl` + `content-discovery` + `scope.yaml` (`oob.collaborator`). `refs/` = `llm_testing_guide.md` (OWASP LLM Top 10 + techniques). Chains FROM web recon; chains TO the 4 LLM variants.
- **DECOMPOSITION:** n/a (feeder).

## Goal
Produce the shared LLM context (model + API + guardrails + tools + data + output sinks + routing).
DONE = `checklist.md` `- [x]` · `review.md` PASS (`llm_context.json` validates against the schema).

## Gate — is there a real LLM behind it? (verify BEFORE routing to the AI variants)
"A chatbot" ≠ "an LLM". Many production bots — especially municipal/enterprise help widgets — are
**scripted intent/NLU/FAQ** engines (canned answers, keyword→intent routing, a vendor widget platform) with
**no generative model**. Prompt-injection, sensitive-disclosure, excessive-agency and output-handling are
**LLM-01..10 classes that simply do not apply** to those — routing them there burns cycles on an impossible
target. So first **classify**, benignly:
- **Generative-LLM signs** → novel/coherent answers to off-script questions, follows reformatting/translation
  instructions, variable phrasing, reasoning, streamed tokens, a model/provider fingerprint.
- **Rule/intent-bot signs** → canned/templated replies, falls back to "I didn't understand" off-script,
  identical answers to paraphrases, a fixed intent list, a known widget vendor, **no** reasoning or novelty.

Record the determination in `llm_context.json` (`llm_backed: true|false` + evidence). If it is **not**
LLM-backed, **do not** route to the AI variants — hand the bot to the **web-app** skills (treat its API as a
normal web backend: `bola-bfla`/`idor` on conversations, `llm-output-handling`→plain XSS via message
rendering, injection on the backend) and note why. (Field lesson: a city chatbot read as "the AI surface"
was a vendor intent bot — the real surface was its web backend + a weak-CSP widget, not prompt injection.)

## What do we want
- **Model** — identify it (ask directly, streamed metadata, behaviour) + provider
- **API** — chat/inference endpoint, client-sent fields (`role`/`content`/`model`/`system`/`tools`), streaming?, other endpoints (completions/models/config/debug/admin/embeddings/plugin-manifests)
- **Guardrails** — input filter / output filter / model-level refusal
- **Tools / agency** (LLM06) — what functions/plugins the LLM can call + their params
- **Data sources** (LLM02/07/08) — RAG, system prompt, memory, uploaded files
- **Output sinks** (LLM05) — where model output flows (HTML render, markdown, DB, code exec, URL fetch)

## Steps  (action · tool · output)
1. Fingerprint the model (direct ask + streamed metadata + behaviour) · interceptor · (into context)
2. Map the chat API + client fields + streaming · interceptor · `api_map.json`
3. Discover LLM endpoints (chat/completions/models/config/debug/admin/embeddings/plugins) · `ffuf` + `refs` · `api_map.json`
4. Classify guardrails (benign refusal probe) · benign probes · `surface_probes.jsonl`
5. Enumerate tools/agency + data sources + output sinks · interceptor + behaviour · `surface_probes.jsonl`
6. Build injection-point map + route (`variant_hint`) · synth · (into context)
7. Consolidate + validate vs schema · synth · `llm_context.json`
8. Emit summary · synth · `summary.md`
9. /REVIEW SKILL · `review.md`

## Tools
- interceptor (chat API), `garak`/`PyRIT` (recon), `ffuf` (endpoint discovery), benign probes
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/out/<site>/findings/`: `endpoints.jsonl`, `apis.jsonl`; `content-discovery` endpoints
- `scope.yaml` (`oob.collaborator`), `refs/llm_testing_guide.md`

## Outputs
`api_map.json` · `surface_probes.jsonl` · `llm_context.json` · `summary.md` · `logs/`

## Phases
- **Phase 1 (generic):** model fingerprint + API/endpoint mapping.
- **Phase 2 (target-specific):** guardrail + tools/agency + data + output-sink mapping + routing.

## Safety
Benign probes only (model ID, guardrail classification with harmless refusals) — NO jailbreaks / harmful
content generation / data exfil here (variants, with benign canaries). Treat model output as UNTRUSTED.
Scope to the authorized LLM app; rate-limit (LLM calls cost); audit-log.
