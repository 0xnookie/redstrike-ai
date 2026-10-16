# SSRF Context (shared feeder)

> RECON / context feeder for the SSRF family (variants: `ssrf-inband`, `ssrf-blind`, `ssrf-cloud`).
> Lightly active (benign OOB probes) → honors `_contract/roe-gate.md` scope on every probe.
> Emits NO findings → `review.md` only, no `verify.md`. Output: `ssrf_context.json`
> (schema `_contract/ssrf_context.schema.json`).

## Interview
- **STEPS:** enumerate URL-fetching sinks → classify each (feature + where the URL goes) → probe fetch behavior with a benign OOB URL → record in-band vs blind + protocol/redirect/allowlist behavior → route each sink to a variant → emit → review.
- **TOOLS:** `jq` over `js-analysis` (params like `url`,`uri`,`src`,`callback`,`webhook`,`dest`,`feed`,`import`), interceptor, `curl` + an OOB host (`interactsh`); `refs/ssrf_surface.md`.
- **GOAL:** Map every server-side URL-fetching sink, its fetch behavior, and whether it reflects the response, into `ssrf_context.json` — so the variant agents start from one analysis. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `fetch_sinks.json`, `behavior_probes.jsonl`, `ssrf_context.json`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/{params.txt,endpoints_*.txt,apis.json}`, `scope.yaml` (`oob.collaborator` + in-scope internal ranges). `refs/` = `ssrf_surface.md`, `ssrf_payloads.md`. Chains FROM `js-analysis`; chains TO `ssrf-inband|blind|cloud`.
- **DECOMPOSITION:** n/a (feeder).

## Goal
Produce the shared SSRF context: candidate fetch sinks + their behavior + variant routing.
DONE = `checklist.md` all `- [x]` · `review.md` PASS (artifacts non-zero, valid JSON; `ssrf_context.json` validates against the schema).

## What do we want
- URL-fetching sinks: param × endpoint × feature (webhook, import-from-url, image/PDF proxy, link preview, SSO/OIDC metadata, avatar-from-url)
- Per sink: does the server fetch it? follow redirects? which protocols? allowlist/parser behavior? **reflect the response in-band?**
- Routing: in-band (response visible) / blind (OOB only) / cloud (reaches metadata)

## Steps  (action · tool · output)
1. Enumerate candidate fetch params/features · `jq` + `grep` js-analysis + `refs/ssrf_surface.md` · `fetch_sinks.json`
2. Probe each with a benign OOB URL; confirm the server fetches it · `curl` + OOB listener · `behavior_probes.jsonl`
3. Characterize behavior (in-band reflection? redirects? protocols? allowlist?) · interceptor · `behavior_probes.jsonl`
4. Route each sink (`variant_hint`) + list in-scope internal targets · synth · (into context)
5. Consolidate + validate vs schema · synth · `ssrf_context.json`
6. Emit summary · synth · `summary.md`
7. /REVIEW SKILL · `review.md`

## Tools
- **Enumerate:** `jq`/`grep` over `js-analysis`, Burp (feature discovery)
- **Probe:** `curl` + OOB (`interactsh-client` / Collaborator), interceptor
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/`: `params.txt`, `endpoints_*.txt`, `apis.json`
- `scope.yaml`: `oob.collaborator`, in-scope internal ranges
- `refs/`: `ssrf_surface.md`, `ssrf_payloads.md`

## Outputs
`fetch_sinks.json` · `behavior_probes.jsonl` · `ssrf_context.json` · `summary.md` · `logs/`

## Phases
- **Phase 1 (generic):** enumerate sinks + benign OOB fetch confirmation.
- **Phase 2 (target-specific):** behavior characterization + variant routing + consolidation.

## Safety
Benign OOB probes only (no internal scanning beyond confirming a fetch) — scope-gate every probe,
rate-limit, audit-log. Exploitation (internal access, metadata creds) is the variants' job, under approval.
