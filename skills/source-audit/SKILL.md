# Source Audit (white-box feeder)

> RECON / white-box feeder. Given AUTHORIZED source access, greps the codebase for dangerous-sink patterns
> across languages + runs `semgrep`, and emits a ROUTED candidate map (file:line → likely vuln class →
> executor) that feeds the vuln executors; also surfaces secret + dependency candidates. STATIC + read-only
> (never executes the code) → honors `_contract/roe-gate.md`. Emits NO findings → `review.md` only.
> Output: `source_context.json` (schema `_contract/source_context.schema.json`). The orchestrator runs this
> ONLY when `scope.yaml` grants authorized source access; a pure black-box run skips it.

## Interview
- **STEPS:** ingest source (provided repo / fetched / `js-analysis` beautified) → detect languages + LOC → per-language dangerous-pattern grep → `semgrep` rulesets → secret + dependency surface → map each candidate to a vuln class → route to the executor that can PROVE it → emit → review.
- **TOOLS:** `rg`/grep (language patterns), `semgrep` (rulesets), `trufflehog` (secret candidates), dependency-manifest parse (`jq`); Solidity source → `web3-context`. Tool-first — `_contract/tooling.md`.
- **GOAL:** Turn source access into a routed candidate map — WHERE the dangerous sinks are and WHICH executor should confirm each — so white-box leads get PROVEN by the executors, never asserted from a grep. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `source_findings.jsonl`, `source_context.json`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = an authorized source repo (`scope.yaml` source ref) + `js-analysis/` beautified JS + `web3-context` source. `refs/` = `source_audit.md`. Chains FROM `scope`/`js-analysis`/`web3-context`; chains TO the per-class context feeders that fan out to the executors — `injection-context` (→ ssti/command-injection/deserialization) · `sqli-context` (→ sqli-*) · `xss-context` (→ xss-*) · `file-context` (→ path-traversal-lfi/upload-rce) — plus `prototype-pollution` (direct) · `secrets` (secret candidates) · `cve-intelligence` (deps) · `web3-context` (Solidity). Each consumer reads `source_context.json` as optional higher-confidence leads.
- **DECOMPOSITION:** n/a (white-box feeder). Black-box sink mapping → `injection-context`/`file-context`/etc.; Solidity source review → `web3-context` + the `sc-*` executors.

## Goal
Produce the routed source candidate map (dangerous sinks + secret/dep candidates → executors). DONE =
`checklist.md` `- [x]` · `review.md` PASS (`source_context.json` validates against the schema).

## What do we want
- **Languages + LOC** — what the codebase is written in (routes the pattern set)
- **Dangerous-sink candidates** — `file:line` + the matched pattern + the vuln class it implies + the executor to route it to (a grep hit is a LEAD, not a finding)
- **Secret candidates** — hardcoded keys/tokens (value redacted) → `secrets`
- **Dependencies** — manifest libs + versions → `cve-intelligence` / `supply-chain`
- **Routing** — executor hints so the right agents fan out

## Steps  (action · tool · output)
1. Ingest + detect languages + LOC · `rg --files` + ext map · (seed)
2. Per-language dangerous-pattern grep (sinks per `refs`) · `rg` + `refs/source_audit.md` · `source_findings.jsonl`
3. Semgrep rulesets (language + security) · `semgrep --config auto` · `source_findings.jsonl`
4. Secret candidates (redact values) + dependency manifests · `trufflehog` + `jq` · `source_findings.jsonl`
5. Map each candidate → vuln class → executor; dedupe · synth · (into context)
6. Consolidate + validate vs schema · synth · `source_context.json`
7. Emit summary · synth · `summary.md`
8. /REVIEW SKILL · `review.md`

## Tools
- `rg`/grep (language dangerous-pattern sets), `semgrep`, `trufflehog` (secret candidates), `jq`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- authorized source repo (`scope.yaml` source ref), `js-analysis/` beautified JS, `web3-context` source
- `refs/source_audit.md`

## Outputs
`source_findings.jsonl` · `source_context.json` · `summary.md` · `logs/`

## Phases
- **Phase 1 (generic):** language detection + dangerous-pattern grep + semgrep.
- **Phase 2 (target-specific):** secret/dependency surface + class mapping + routing.

## Safety
**Read-only static review — NEVER execute the source.** White-box: requires authorized source access (scope).
A grep/semgrep hit is a **CANDIDATE** to be confirmed by the routed executor against the running target — not a
finding on its own (no runtime proof here). Redact secret **values** to fingerprints (hand the live-check to
`secrets`); hand dependency versions to `cve-intelligence`. Scope-gate; audit-log.
