# Clickjacking Agent

> ATOMIC single agent (no feeder) — one confirmation: a security-sensitive action is frameable and
> can be driven via UI redress.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md`; carries `review.md` + `verify.md`.

## Interview
- **STEPS:** enumerate sensitive UI actions → check framing defenses per page → identify frameable sensitive pages → build framing PoC → confirm frames + action reachable → rate → emit → review → verify.
- **TOOLS:** `curl -I`/`httpx` (XFO + CSP `frame-ancestors`), `chrome-devtools-mcp`/`puppeteer` (render the frame), `jq`.
- **GOAL:** Confirm clickjacking — a page carrying a security-sensitive, state-changing action lacks (or bypasses) framing protection and a UI-redress PoC can drive it. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `framing_tests.json`, `findings.json`, `poc/`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/out/<site>/findings/endpoints.jsonl` (sensitive actions), `scope.yaml`. `refs/` = `framing_poc.md`. Chains FROM `js-analysis`; chains TO `reporting`. Pairs with `csrf` (framed CSRF).
- **DECOMPOSITION:** n/a (atomic).

## Goal
Find security-sensitive pages that can be framed and clickjacked, and prove it with a UI-redress PoC.
Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` all `- [x]` · `review.md` PASS · every finding accepted.

## What do we want
- Sensitive, state-changing UI actions (delete, transfer, grant, change settings)
- Per page: `X-Frame-Options` + CSP `frame-ancestors` present? bypassable?
- A framing PoC that overlays/redirects a victim click onto the sensitive control

## Steps  (action · tool · output)
1. Enumerate sensitive UI actions (from js-analysis + crawl) · `jq` + crawl · `framing_tests.json`
2. Check framing defenses per page (`XFO`, CSP `frame-ancestors`) · `curl -I`/`httpx` · `framing_tests.json`
3. Build framing PoC (iframe + opacity overlay / decoy) · `refs/framing_poc.md` · `poc/<id>/poc.html`
4. Confirm the page frames and the action is reachable through the frame · `chrome-devtools-mcp` · `poc/<id>/` evidence
5. Rate (CVSS) + write finding · synth · `findings.json`
6. Emit report · synth · `report.md`
7. /REVIEW · `review.md` · 8. /VERIFY · `verify.md`

## Tools
- **Defenses/confirm:** `curl -I`, `httpx`, `chrome-devtools-mcp`/`puppeteer`, `refs/framing_poc.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/`: `endpoints_*.txt`, routes (sensitive actions)
- `scope.yaml`, `refs/framing_poc.md`

## Outputs
`framing_tests.json` · `findings.json` · `poc/` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** enumerate sensitive actions + framing-defense matrix.
- **Phase 2 (target-specific):** framing PoC + reachability confirmation + rating.

## Safety
PoC is a local HTML page (non-destructive). Don't actually perform the state change against a real
account — demonstrate framing + click reachability on a test account. Scope-gate; audit-log.
