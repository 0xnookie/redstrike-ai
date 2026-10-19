# XXE Context (shared feeder)

> RECON / context feeder for the XXE family (variants: `xxe-inband`, `xxe-blind`).
> ACTIVE (benign entity probes) → honors `_contract/roe-gate.md`. Emits NO findings → `review.md` only.
> Output: `xxe_context.json` (schema `_contract/xxe_context.schema.json`).

## Interview
- **STEPS:** enumerate XML-accepting endpoints/uploads → send a benign INTERNAL entity → confirm the parser resolves entities → note error reflection → route → emit → review.
- **TOOLS:** interceptor, `jq` over `js-analysis`, `refs/xxe_payloads.md`.
- **GOAL:** Map endpoints that parse XML (SOAP, XML APIs, SVG/DOCX/XLSX uploads, SAML, RSS) and whether the parser resolves external entities, into `xxe_context.json`. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `xml_sinks.json`, `entity_probes.jsonl`, `xxe_context.json`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/out/<site>/findings/{endpoints,apis}.jsonl` (XML content-types, upload features) + `scope.yaml` (`oob.collaborator`). `refs/` = `xxe_payloads.md`. Chains FROM `js-analysis`; chains TO `xxe-inband`, `xxe-blind`.
- **DECOMPOSITION:** n/a (feeder).

## Goal
Produce the shared XXE context (XML sinks + entity-resolution behavior + routing).
DONE = `checklist.md` `- [x]` · `review.md` PASS (`xxe_context.json` validates against the schema).

## What do we want
- XML-parsing surfaces: `Content-Type: application/xml|text/xml|soap+xml`, SVG/DOCX/XLSX uploads, SAML, RSS
- Whether the parser resolves entities (benign internal entity reflected) + error visibility
- Routing: in-band (reflection/error) vs blind (OOB only)

## Steps  (action · tool · output)
1. Enumerate XML-accepting endpoints/uploads · `jq`/`grep` js-analysis + content-type probe · `xml_sinks.json`
2. Send a benign INTERNAL entity (`<!ENTITY x "RS"> ...&x;`) · interceptor · `entity_probes.jsonl`
3. Confirm resolution (entity value appears) + note error reflection · interceptor · `entity_probes.jsonl`
4. Route each sink (`variant_hint`) · synth · (into context)
5. Consolidate + validate vs schema · synth · `xxe_context.json`
6. Emit summary · synth · `summary.md`
7. /REVIEW SKILL · `review.md`

## Tools
- interceptor, `jq`/`grep` over `js-analysis`, `refs/xxe_payloads.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/out/<site>/findings/`: `endpoints.jsonl`, `apis.jsonl`
- `scope.yaml` (`oob.collaborator`), `refs/xxe_payloads.md`

## Outputs
`xml_sinks.json` · `entity_probes.jsonl` · `xxe_context.json` · `summary.md` · `logs/`

## Phases
- **Phase 1 (generic):** enumerate XML sinks + benign internal-entity resolution probe.
- **Phase 2 (target-specific):** error/reflection characterization + routing.

## Safety
Benign INTERNAL entities only for detection — NO external file reads / SSRF here (variants, approval).
**Never** send billion-laughs/entity-expansion DoS payloads. Scope-gate; rate-limit; audit-log.
