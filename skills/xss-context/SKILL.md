# XSS Context (shared feeder)

> RECON / context feeder. Produces the ONE shared analysis the four XSS variant
> agents (reflected / stored / dom / blind) fan out from — this skill is what
> PREVENTS those variants from each becoming a monolith.
> Lightly active (benign markers only, non-destructive) → honors `_contract/roe-gate.md`
> scope check on every probe; no approval gate. Emits NO findings → `review.md` only, no `verify.md`.

## Interview
- **STEPS:** ingest surface → expand injection surface → benign marker probe (all sources) → persistence check → classify reflection context → capture CSP/headers → map DOM source→sink flows → consolidate → emit summary + routing → review.
- **TOOLS:** see §Tools (ingest js-analysis, `arjun`/`x8`, `kxss`/`Gxss`, interceptor, `chrome-devtools-mcp`, `httpx`, modern-first + ladder).
- **GOAL:** Produce the shared XSS context — every candidate injection point with its reflection/persistence behavior and context, the DOM source→sink flows, and the CSP posture — as `xss_context.json`, so the four variant agents start from one analysis instead of re-deriving it. Done = all checklist boxes checked AND review passes.
- **OUTPUT:** `candidate_points.json`, `reflections.jsonl`, `csp.json`, `dom_flows.json`, `xss_context.json`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/` (`endpoints_{live,unauthed}.txt`, `params.txt`, `gadgets.md`, `js/beautified/`) + optional `auth.env` + `scope.yaml` (incl. `oob.collaborator`). `refs/` = `injection_surface.md`, `context_rules.md`. Output contract = `_contract/xss_context.schema.json`. Chains FROM `js-analysis`; chains TO `xss-reflected`, `xss-stored`, `xss-dom`, `xss-blind`.
- **DECOMPOSITION:** n/a (shared feeder, not a vuln class).

## Goal
Build the shared XSS context (`xss_context.json`, schema `_contract/xss_context.schema.json`)
that routes each candidate to the right variant agent.
DONE = `checklist.md` all `- [x]` AND `review.md` PASS (artifacts exist, non-zero, valid JSON).

## What do we want
- Injection points: endpoint × param × source (query / body / path / header / cookie / fragment)
- Per point: does it reflect? is it encoded/sanitized? does it persist? in what context?
- DOM: sources, dangerous sinks, and source→sink flows (DOM-XSS candidates)
- CSP posture: does it block inline / eval? Trusted Types? bypassable sources?
- Routing: which variant(s) each point feeds (`variant_hint`)

## Steps  (action · tool · output)
1. Ingest attack surface from js-analysis (endpoints, params, forms, gadgets) · `jq` over js-analysis outputs · `candidate_points.json`
2. Expand injection surface (every source: query/body/path/header/cookie/fragment; JSON keys; forms) · `refs/injection_surface.md` + `arjun`/`x8` · `candidate_points.json` (expanded)
3. Benign marker probe per (point, source); record where/if it reflects · `kxss`/`Gxss` + custom marker + ladder fetch · `reflections.jsonl`
4. Persistence check — does the marker resurface on another view/endpoint? (→ stored candidate) · re-fetch related views + interceptor · `reflections.jsonl` (persist flags)
5. Classify reflection context per hit; canary-probe which breakout chars are encoded · `refs/context_rules.md` + DOM inspect · (into `injection_points`)
6. Capture CSP + security headers; assess block-inline/eval + bypassable sources · `httpx -include` / `curl -I` + policy parse · `csp.json`
7. Map DOM sources, sinks, and source→sink flows · `chrome-devtools-mcp` + `gadgets.md` · `dom_flows.json`
8. Consolidate + validate against the schema · synth + schema check · `xss_context.json`
9. Emit summary + per-point variant routing · synth · `summary.md`
10. /REVIEW SKILL · `review.md`

## Tools
- **Ingest:** `jq`, `ripgrep` over `js-analysis/` outputs
- **Param expand/confirm:** `arjun`, `x8`
- **Reflection:** `kxss`, `Gxss`, custom marker probe
- **Persistence/context:** interceptor (Caido / mitmproxy), `chrome-devtools-mcp` (live DOM)
- **CSP/headers:** `httpx -include`, `curl -I`, `nuclei` (`http/misconfiguration/http-missing-security-headers`)
- **DOM flows:** `chrome-devtools-mcp`, `gadgets.md` (from js-analysis), `semgrep`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/`: `endpoints_live.txt`, `endpoints_unauthed.txt`, `params.txt`, `gadgets.md`, `js/beautified/`
- optional `auth.env` (authed surface)
- `scope.yaml` (RoE scope check per probe; `oob.collaborator` for blind routing)
- `refs/`: `injection_surface.md`, `context_rules.md`
- output contract: `_contract/xss_context.schema.json`

## Outputs
`candidate_points.json` · `reflections.jsonl` · `csp.json` · `dom_flows.json` · `xss_context.json` · `summary.md` · `logs/`

## Phases
- **Phase 1 (generic):** ingest + surface expansion + benign marker probe + CSP capture.
- **Phase 2 (target-specific):** context classification + persistence + DOM flow mapping + consolidation + routing.

## Safety
Benign markers only (non-destructive) — but still ACTIVE: every probe resolves its target
and checks `scope.yaml` first (hard stop if out of scope / window closed), rate-limited per RoE,
audit-logged. No human approval gate (that is for exploitation). Confirmation and findings are
the downstream variants' job — this skill deliberately produces none.
