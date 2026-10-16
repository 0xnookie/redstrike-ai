# Stored XSS Agent

> ONE variant agent of the XSS class (siblings: `xss-reflected`, `xss-dom`, `xss-blind`).
> First CONSUMER of the `xss-context` feeder — ingests `xss_context.json` points where
> `persists == true`. ACTIVE + findings-producing → imports `_contract/roe-gate.md` and
> carries BOTH `review.md` (mechanical) and `verify.md` (semantic).
> Stored XSS has real blast radius (it sits on a surface and can fire on OTHER users) —
> see §Safety; this is the one variant where test-payload hygiene and cleanup matter.

## Interview
- **STEPS:** ingest stored candidates → map injection→render pairs (+ viewer privilege) → submit benign tracer → locate render surface(s) → classify context AT THE RENDER SURFACE → select payload → probe store+output sanitizers → confirm EXECUTION on the render surface as a DIFFERENT user → capture PoC at both ends → assess durability/blast radius → rate → emit findings → cleanup → review → verify.
- **TOOLS:** ingest `xss_context.json` (`jq`); crawl render surfaces (`katana`, `chrome-devtools-mcp`); multi-identity (two sessions via `auth.env`, `puppeteer` profiles); store↔render tracing (interceptor Caido/mitmproxy, tracer markers); execution confirm (`chrome-devtools-mcp` → `puppeteer`); sanitizer bypass (custom + `dalfox`); OOB for unseen surfaces. Fetch via `_contract/anti-automation-ladder.md`.
- **GOAL:** Confirm and evidence stored (persistent) XSS — input stored via one request that EXECUTES when a (preferably different) user views the render surface — with PoC captured at BOTH the store and render ends. Done = all checklist boxes checked, `review.md` passes, every finding `review.verdict = accepted`.
- **OUTPUT:** `stored_candidates.json`, `render_map.json`, `tracers.jsonl`, `payloads_tried.jsonl`, `findings.json`, `poc/`, `cleanup.md`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `xss_context.json` (`persists`/`persist_surface`) + `js-analysis/endpoints_*.txt` + `auth.env` (**multi-identity**: ≥2 accounts, or an authorized admin view) + `scope.yaml` (`oob.collaborator`). `refs/` = `render_surfaces.md`, `stored_payloads.md`. Chains FROM `xss-context`; chains TO `reporting`.
- **DECOMPOSITION:** this IS the stored variant. Boundary: if the render surface is unreachable by the tester (admin-only) → hand off to `xss-blind` (OOB). De-dupe with `xss-reflected` when a param is both.

## Goal
Find stored XSS: attacker input persisted via a store request that executes on a render
surface viewed by another user. Confirm in a real browser as a different session; emit an
evidenced `findings.json` (schema `_contract/finding.schema.json`).
DONE = `checklist.md` all `- [x]` · `review.md` PASS · every finding `review.verdict = accepted`.

## What do we want
- Store→render pairs: where input is stored (endpoint A) and where it renders back (surface B)
- Viewer context for B: same-user / other-user / admin / anonymous (the impact multiplier)
- Render-surface context + output sanitizer behavior
- A payload that survives storage AND output filtering and EXECUTES on B
- Cross-session PoC (store as attacker, execute as victim) + durability + blast radius
- CVSS (stored typically ranks above reflected) + cleanup record

## Steps  (action · tool · output)
1. Ingest stored candidates from the feeder (`persists == true` + accepted-but-unseen) · `jq xss_context.json` · `stored_candidates.json`
2. Enumerate render surfaces + viewer privilege for each candidate · `refs/render_surfaces.md` + crawl (`katana`/`chrome-devtools-mcp`) · `render_map.json`
3. Submit a benign unique tracer to each store point · ladder fetch + interceptor · `tracers.jsonl`
4. Locate where each tracer renders (which surface, which viewer) · crawl as each identity · `render_map.json` (confirmed pairs)
5. Classify context AT THE RENDER SURFACE; canary the output encoder/sanitizer · `refs/context_rules.md`(xss-context) + DOM inspect · (into findings draft)
6. Select payload; probe store-side AND output-side sanitizers · `refs/stored_payloads.md` + `dalfox` · `payloads_tried.jsonl`
7. Confirm EXECUTION on the render surface as a DIFFERENT user/session · `chrome-devtools-mcp` → `puppeteer` (second profile) · `poc/<id>/render_*.{png,dom}`
8. Capture the store request + the render evidence (both ends) · interceptor + browser · `poc/<id>/store_req.http` + render evidence
9. Assess durability (survives logout/new session) + blast radius (who sees it) · re-test fresh session · (into findings)
10. Rate (CVSS) + write finding · synth · `findings.json`
11. Record stored artifacts + removal steps · synth · `cleanup.md`
12. Emit report + PoCs · synth + `printf` · `report.md`, `curl_commands.sh`
13. /REVIEW SKILL (mechanical) · `review.md` → `verify_completion.py`
14. /VERIFY (semantic) · `verify.md` (subagent)

## Tools
- **Ingest:** `jq` over `xss_context.json`
- **Render mapping / crawl:** `katana`, `chrome-devtools-mcp`
- **Multi-identity (required):** `auth.env` (≥2 accounts), `puppeteer`/`playwright` profiles, or an authorized admin viewer
- **Store↔render trace:** interceptor (Caido / mitmproxy), unique tracers
- **Execution confirm:** `chrome-devtools-mcp` → `puppeteer` (second session)
- **Sanitizer bypass:** custom, `dalfox` (stored/deep), mutation-XSS for HTML sanitizers
- **Unseen surfaces:** OOB (`oob.collaborator`) → consider `xss-blind` handoff
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `xss_context.json` (points with `persists: true`, `persist_surface`) — schema `_contract/xss_context.schema.json`
- `js-analysis/`: `endpoints_live.txt`, `endpoints_unauthed.txt`
- `auth.env` — **two identities minimum** (attacker + victim), ideally incl. an admin view if authorized
- `scope.yaml` (RoE gate; `oob.collaborator`)
- `refs/`: `render_surfaces.md`, `stored_payloads.md`

## Outputs
`stored_candidates.json` · `render_map.json` · `tracers.jsonl` · `payloads_tried.jsonl` · `findings.json` · `poc/` · `cleanup.md` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** candidate ingest + render-surface mapping + benign tracer placement + pair confirmation.
- **Phase 2 (target-specific):** payload/sanitizer bypass + cross-user execution confirmation + PoC capture + durability/blast-radius + rating + cleanup.

## Safety
Active AND persistent — higher blast radius than any other XSS variant: a stored payload
sits on the surface and can fire on **real users/staff**, and persists beyond the test window.
Therefore:
- **Benign payloads only.** Confirm with `alert`/`print`/an OOB canary. Never a self-propagating,
  credential-stealing, or action-performing payload against real users.
- **Scope to test accounts** where a surface is shared; if the only render surface is one that
  real users or admins hit, treat as higher-risk and get **approval** (RoE `no_destructive` +
  `prod_touch_requires_approval`).
- **Record and clean up.** Every stored artifact goes in `cleanup.md` with removal steps; remove
  test payloads at the end of the window unless the client asked to retain evidence.
- Scope-gate every store/render request; rate-limit; audit-log.
