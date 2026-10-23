# Injection Context (shared feeder)

> RECON / context feeder for the injection family (variants: `ssti`, `command-injection`, `deserialization`).
> ACTIVE (benign probes) → honors `_contract/roe-gate.md`. Emits NO findings → `review.md` only.
> Output: `injection_context.json` (schema `_contract/injection_context.schema.json`).

## Interview
- **STEPS:** enumerate reflective/processing params → benign-probe for interpreter sinks (template math, command metachars, serialized markers) → fingerprint engine/tech → classify sink type → route → emit → review.
- **TOOLS:** `jq` over `js-analysis/out/<site>/findings/`, interceptor, `refs/injection_payloads.md`; `js-analysis/out/<site>/analysis/site-summary.md` (stack).
- **GOAL:** Map injection points that reach an interpreter (template / OS command / deserializer), fingerprint the engine, and route to a variant, into `injection_context.json`. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `candidates.json`, `probes.jsonl`, `injection_context.json`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/out/<site>/findings/{params,apis}.jsonl` + `js-analysis/out/<site>/analysis/site-summary.md` (stack) + `scope.yaml` (`oob.collaborator`). `refs/` = `injection_payloads.md`. Also ingests optional `source-audit/source_context.json` (white-box interpreter-sink candidates for this family, if source was audited — merge as higher-confidence leads the executor still PROVES). Chains FROM `js-analysis` (+ `source-audit` when source is in scope); chains TO `ssti`, `command-injection`, `deserialization`.
- **DECOMPOSITION:** n/a (feeder).

## Goal
Produce the shared injection context (interpreter sinks + engine fingerprint + routing).
DONE = `checklist.md` `- [x]` · `review.md` PASS (`injection_context.json` validates against the schema).

## What do we want
- Params whose value reaches a **template engine** (`{{7*7}}`→49), an **OS command** (metachar reaction),
  or a **deserializer** (serialized-object markers accepted)
- Engine/tech fingerprint (jinja2/twig/freemarker/velocity; java/php/python ser)
- Sink type + variant routing

## Steps  (action · tool · output)
1. Enumerate reflective/processing params · `jq`/`grep` js-analysis · `candidates.json`
2. Benign-probe interpreter sinks (`{{7*7}}`,`${7*7}`,`#{7*7}`; `;`,`|`,`` ` ``; base64 serialized marker) · interceptor · `probes.jsonl`
3. Fingerprint engine (reaction patterns + `site-summary.md` stack) · `refs/injection_payloads.md` · `probes.jsonl`
4. Classify sink type + route (`variant_hint`) · synth · (into context)
5. Consolidate + validate vs schema · synth · `injection_context.json`
6. Emit summary · synth · `summary.md`
7. /REVIEW SKILL · `review.md`

## Tools
- `jq`/`grep` over `js-analysis`, interceptor, `refs/injection_payloads.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/out/<site>/`: `findings/params.jsonl`, `findings/apis.jsonl`, `analysis/site-summary.md`
- `scope.yaml` (`oob.collaborator`), `refs/injection_payloads.md`

## Outputs
`candidates.json` · `probes.jsonl` · `injection_context.json` · `summary.md` · `logs/`

## Phases
- **Phase 1 (generic):** enumerate + benign interpreter-sink probing.
- **Phase 2 (target-specific):** engine fingerprint + sink classification + routing.

## Safety
Benign detection probes ONLY (arithmetic / metachar reaction / marker acceptance) — NO command
execution or RCE payloads here (that's the variants, approval-gated, with benign proof). Scope-gate;
rate-limit; audit-log.
