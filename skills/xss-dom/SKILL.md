# DOM XSS Agent

> ONE variant agent of the XSS class (siblings: `xss-reflected`, `xss-stored`, `xss-blind`).
> Consumes `xss_context.json` `dom.source_sink_flows` + `dom.sources`/`sinks`, and does its own
> taint analysis over `js-analysis/out/<site>/beautified/`. Includes GADGET GATHERING (per the class spec).
> ACTIVE + findings-producing → imports `_contract/roe-gate.md`; carries BOTH `review.md` + `verify.md`.
> Confirms entirely CLIENT-SIDE (no server round-trip) → lowest blast radius of the variants.

## Interview
- **STEPS:** ingest DOM candidates → gather gadgets (source→sink chains, postMessage handlers, prototype-pollution sinks) → taint-trace each flow → craft source delivery → probe sink filters / Trusted Types → confirm execution in a real browser → capture client-only PoC → rate → emit findings → review → verify.
- **TOOLS:** ingest `xss_context.json` (`jq`); taint analysis `semgrep` + `chrome-devtools-mcp` (DOM/event breakpoints) + custom; gadget discovery over `js-analysis/out/<site>/beautified/` + `findings/gadgets.jsonl`; postMessage harness; confirm `chrome-devtools-mcp` → `puppeteer`; `Burp DOM Invader` (alt). Fetch via `_contract/anti-automation-ladder.md`.
- **GOAL:** Confirm DOM-based XSS where an attacker-controllable client-side source flows to a dangerous sink and executes ENTIRELY in the browser (no server reflection), with a reproducible crafted-URL / `postMessage` PoC. Done = all checklist boxes checked, `review.md` passes, every finding `review.verdict = accepted`.
- **OUTPUT:** `dom_candidates.json`, `gadgets.md`, `taint_flows.json`, `payloads_tried.jsonl`, `findings.json`, `poc/`, `poc_urls.txt`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = `xss_context.json` (`dom.*`) + `js-analysis/out/<site>/` (`beautified/`, `findings/gadgets.jsonl`) + `scope.yaml`. `refs/` = `dom_sources_sinks.md`, `dom_payloads.md`. Chains FROM `xss-context` (+ js-analysis beautified JS); chains TO `reporting`.
- **DECOMPOSITION:** this IS the DOM variant; includes gadget gathering. Boundary: if the sink value actually originates from a server response → that is `xss-reflected`/`xss-stored`, reclassify. De-dupe across siblings.

## Goal
Find DOM XSS: an attacker-controllable source (hash / search / `postMessage` / `window.name` / …)
reaches a dangerous sink and executes client-side. Confirm in a real browser; emit an evidenced
`findings.json` (schema `_contract/finding.schema.json`).
DONE = `checklist.md` all `- [x]` · `review.md` PASS · every finding `review.verdict = accepted`.

## What do we want
- Controllable sources reaching dangerous sinks (the taint path, through which functions)
- Gadgets: library source→sink chains, `postMessage` handlers missing origin checks, prototype-pollution → gadget sinks
- A payload delivered via the source that executes at the sink (Trusted-Types / CSP aware)
- Client-only PoC (crafted URL or `postMessage` script) — no server state
- CVSS + classification distinguishing this from reflected/stored

## Steps  (action · tool · output)
1. Ingest DOM candidates (flows + sources + sinks) from the feeder · `jq xss_context.json` · `dom_candidates.json`
2. Gather gadgets: scan beautified JS for source→sink chains, `postMessage` handlers w/o origin check, prototype-pollution sinks · `semgrep` + `grep` over `findings/gadgets.jsonl` + custom · `gadgets.md`
3. Taint-trace each candidate flow (source → … → sink) · `chrome-devtools-mcp` DOM/event breakpoints + manual · `taint_flows.json`
4. Craft source delivery (hash / search / `window.name` / `postMessage` / storage) · `refs/dom_payloads.md` · (into attempts)
5. Probe sink filters / encoding / Trusted Types · `refs/` + devtools · `payloads_tried.jsonl`
6. Confirm execution at the sink in a real browser · `chrome-devtools-mcp` → `puppeteer` · `poc/<id>/`
7. Capture client-only PoC (crafted URL or `postMessage` script) + devtools taint trace · browser · `poc/<id>/`, `poc_urls.txt`
8. Rate (CVSS) + write finding · synth · `findings.json`
9. Emit report + PoCs · synth · `report.md`, `poc_urls.txt`
10. /REVIEW SKILL (mechanical) · `review.md` → `verify_completion.py`
11. /VERIFY (semantic) · `verify.md` (subagent)

## Tools
- **Ingest:** `jq` over `xss_context.json`
- **Taint / confirm:** `chrome-devtools-mcp` (DOM, event-listener, and XHR breakpoints), `puppeteer`/`playwright`, `Burp DOM Invader` (alt)
- **Gadgets:** `semgrep` + `ripgrep` over `js-analysis/out/<site>/beautified/`, `findings/gadgets.jsonl` (from js-analysis), prototype-pollution + `postMessage` scanners
- **Delivery:** crafted URL (hash/search), `window.name`, `document.referrer` (attacker page), `postMessage` harness
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `xss_context.json`: `dom.sources`, `dom.sinks`, `dom.source_sink_flows` — schema `_contract/xss_context.schema.json`
- `js-analysis/out/<site>/`: `beautified/`, `findings/gadgets.jsonl`
- `scope.yaml` (RoE — scope-gate page loads)
- `refs/`: `dom_sources_sinks.md`, `dom_payloads.md`

## Outputs
`dom_candidates.json` · `gadgets.md` · `taint_flows.json` · `payloads_tried.jsonl` · `findings.json` · `poc/` · `poc_urls.txt` · `report.md` · `logs/`

> No `curl_commands.sh` here: DOM XSS PoCs are crafted URLs / `postMessage` scripts, not curl
> invocations. `poc_urls.txt` carries the one-click PoC URLs instead (contract fits the technique).

## Phases
- **Phase 1 (generic):** ingest + gadget gathering + taint tracing (static + DOM breakpoints).
- **Phase 2 (target-specific):** source delivery + sink/Trusted-Types bypass + execution confirmation + PoC + rating.

## Safety
Lowest blast radius of the XSS variants: `fragment`/`window.name`/`postMessage` sources are
client-side and (for hash) never reach the server, so confirmation often sends NO payload to the
target at all. Still scope-gate every page load; keep payloads benign (`print()`/`window.__rs`).
No stored concern, no approval gate.
