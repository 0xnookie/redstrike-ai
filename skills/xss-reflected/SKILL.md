# Reflected XSS Agent

> ONE variant agent of the XSS class (siblings: `xss-stored`, `xss-dom`, `xss-blind`).
> All four fan out from a shared `xss-context` feeder — never a monolith.
> ACTIVE skill: sends payloads → imports `_contract/roe-gate.md` (scope gate + rate-limit).
> Findings-producing → carries BOTH `review.md` (mechanical) and `verify.md` (semantic).

## Interview
- **STEPS:** ingest context → enumerate injection points → reflection probe (unique markers) → classify context → select payloads (per context) → probe filters/WAF (escalate encodings) → confirm EXECUTION in a real browser → capture PoC → rate (CVSS) → emit findings → review → verify.
- **TOOLS:** reflection detection `kxss`/`Gxss` or custom marker probing; param confirm `arjun`/`x8`; scan/confirm `dalfox`, `nuclei` (`dast/vulnerabilities/xss`, `fuzzing/`); execution confirm `chrome-devtools-mcp` → `puppeteer` (real DOM exec); fetch via `_contract/anti-automation-ladder.md`; manual context via interceptor (Caido/mitmproxy).
- **GOAL:** Confirm and evidence reflected XSS on in-scope endpoints — each with a reproducible PoC that demonstrates **script execution in a real browser**, not mere reflection. Done = all checklist boxes checked, `review.md` passes (liveness), AND `verify.md` accepts each finding (semantic).
- **OUTPUT:** `injection_points.txt`, `reflections.txt`, `contexts.json`, `payloads_tried.jsonl`, `findings.json`, `poc/` (per-finding req/resp + screenshot + DOM), `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/` outputs (`endpoints_{live,unauthed}.txt`, `params.txt`, `gadgets.md`) + optional `xss_context.json` (shared XSS feeder) + `auth.env`. `refs/` = `payloads_by_context.md`, `waf_bypass_encodings.md`. Chains FROM `js-analysis` (+ `xss-context`); chains TO `reporting`.
- **DECOMPOSITION:** this IS the reflected variant. Shared feeder `xss-context` writes `xss_context.json` (injection points + sinks + CSP), consumed by all four variants so they don't each re-derive it.

## Goal
Find reflected XSS where attacker-controlled input is reflected into a response in a
context that **executes**, confirm it in a headless browser, and emit an evidenced
`findings.json` (schema: `_contract/finding.schema.json`).
DONE = `checklist.md` all `- [x]` · `review.md` PASS · every finding `review.verdict = accepted`.

## What do we want
- Injection points (endpoint + param) that reflect input
- Reflection context per point (HTML body / attribute quoted|unquoted / JS string / URI / comment)
- A working, CSP-aware payload that **executes** (not just reflects)
- A reproducible PoC per finding (crafted URL + browser-execution evidence)
- CVSS rating + remediation

## Steps  (action · tool · output)
1. Ingest context (injection points, sinks, CSP) from feeder/js-analysis · read `xss_context.json` + `params.txt` + `endpoints_*.txt` · `injection_points.txt`
2. Confirm params actually reflect; mine extra params · `arjun`/`x8` + marker probe · `injection_points.txt` (refined)
3. Reflection probe with a unique marker (e.g. `rs7f3q`) per point · `kxss`/`Gxss` + ladder fetch · `reflections.txt`
4. Classify reflection context (where the marker landed) · analyze response + DOM · `contexts.json`
5. Select payloads per context · `refs/payloads_by_context.md` · (feeds step 6)
6. Probe filters/WAF; escalate encodings only as needed · `refs/waf_bypass_encodings.md` + `dalfox` · `payloads_tried.jsonl`
7. Confirm EXECUTION in a real browser (alert/DOM-mutation/callback hook) · `chrome-devtools-mcp` → `puppeteer` · `poc/<id>/` (screenshot + dom_capture)
8. Capture request/response for the working payload · ladder + interceptor · `poc/<id>/req_resp.http`
9. Rate (CVSS) + write finding · synth · `findings.json`
10. Emit report + runnable PoCs · synth + `printf` · `report.md`, `curl_commands.sh`
11. /REVIEW SKILL (mechanical) · `review.md` → `verify_completion.py`
12. /VERIFY (semantic) · `verify.md` (subagent) → fills each finding's `review{}` block

## Tools
- **Reflection/param:** `kxss`, `Gxss`, `arjun`, `x8`, custom marker probe
- **Scan/confirm:** `dalfox`, `nuclei` (`dast/vulnerabilities/xss`, `fuzzing/`)
- **Execution confirm (required for Medium+):** `chrome-devtools-mcp` (headless, hook `alert`/`print`/DOM mutation), escalate to `puppeteer`/`playwright` for event-gated contexts
- **Fetch ladder:** `_contract/anti-automation-ladder.md`
- **Context/manual:** interceptor (Caido / mitmproxy)

## Inputs
- `xss_context.json` (from `xss-context` feeder; schema `_contract/xss_context.schema.json`) — preferred; else derive from:
- `js-analysis/`: `endpoints_live.txt`, `endpoints_unauthed.txt`, `params.txt`, `gadgets.md`
- optional `auth.env` (authed reflection surface)
- `scope.yaml` (RoE gate — every target checked before a payload is sent)
- `refs/`: `payloads_by_context.md`, `waf_bypass_encodings.md`

## Outputs
`injection_points.txt` · `reflections.txt` · `contexts.json` · `payloads_tried.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** ingest + reflection mapping + context classification (passive-ish; markers only).
- **Phase 2 (target-specific):** payload selection + filter/WAF bypass + execution confirmation + PoC capture + rating.

## Safety
Active skill. Before any payload: resolve target, check `scope.yaml` (hard stop if out of scope / window closed), rate-limit per RoE, default to benign markers before weaponized payloads. Reflected-XSS confirmation is non-destructive — no human approval gate (that is for `exploitation`/`post-exploitation`) — but it is fully scope-gated and audit-logged.
