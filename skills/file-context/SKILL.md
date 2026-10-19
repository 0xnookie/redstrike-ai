# File/Path Context (shared feeder)

> RECON / context feeder for the file/path family (variants: `path-traversal-lfi`, `upload-rce`).
> ACTIVE (benign probes) → honors `_contract/roe-gate.md`. Emits NO findings → `review.md` only.
> Output: `file_context.json` (schema `_contract/file_context.schema.json`).

## Interview
- **STEPS:** enumerate file/path params + upload endpoints → benign-probe traversal behavior → characterize uploads (allowed types, stored path, web-reachable, executes?) → route → emit → review.
- **TOOLS:** `jq` over `js-analysis`, interceptor, `refs/file_payloads.md`.
- **GOAL:** Map file-read/include params and upload endpoints + their handling into `file_context.json`. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `file_sinks.json`, `probes.jsonl`, `file_context.json`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/out/<site>/findings/{params,endpoints}.jsonl` (path-ish params from `param_wordlist` file/path group; upload features) + `scope.yaml`. `refs/` = `file_payloads.md`. Chains FROM `js-analysis`; chains TO `path-traversal-lfi`, `upload-rce`.
- **DECOMPOSITION:** n/a (feeder).

## Goal
Produce the shared file/path context (file sinks + upload handling + routing).
DONE = `checklist.md` `- [x]` · `review.md` PASS (`file_context.json` validates against the schema).

## What do we want
- File-read/include params (`file`,`path`,`template`,`include`,`page`,`doc`,`download`)
- Upload endpoints: allowed types, where the file is stored, whether that path is web-reachable + executable
- Routing: traversal/LFI vs upload-to-RCE

## Steps  (action · tool · output)
1. Enumerate file/path params + upload endpoints · `jq`/`grep` js-analysis · `file_sinks.json`
2. Benign traversal probe (`../`, encoded, a known marker path) · interceptor · `probes.jsonl`
3. Characterize uploads (type checks, stored path, web-reach, exec) · interceptor · `probes.jsonl`
4. Route each sink (`variant_hint`) · synth · (into context)
5. Consolidate + validate vs schema · synth · `file_context.json`
6. Emit summary · synth · `summary.md`
7. /REVIEW SKILL · `review.md`

## Tools
- `jq`/`grep` over `js-analysis`, interceptor, `refs/file_payloads.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/`: `params.txt`, `endpoints_*.txt`
- `scope.yaml` (`oob.collaborator`), `refs/file_payloads.md`

## Outputs
`file_sinks.json` · `probes.jsonl` · `file_context.json` · `summary.md` · `logs/`

## Phases
- **Phase 1 (generic):** enumerate sinks + benign traversal/upload probing.
- **Phase 2 (target-specific):** upload handling characterization + routing.

## Safety
Benign probes — read a NON-sensitive marker path for traversal detection; characterize uploads WITHOUT
uploading an executable yet (that's `upload-rce`, approval). Scope-gate; rate-limit; audit-log.
