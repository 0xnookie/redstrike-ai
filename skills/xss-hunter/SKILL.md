# XSS Hunter

> TIER-3 MISSION agent (single-class) — inherits `_contract/hunter-base.md`. A depth-first entry point
> that hunts ONE class: XSS. `bug-bounty` pinned to XSS — SAME machinery (the `xss-context` feeder + the
> four variants + their reviewers + packaging), narrower scope, deeper iteration. Owns the program's
> scope + rules. Drives the XSS family; findings come from the gated variant agents → emits NO findings
> of its own → `review.md` only, no `verify.md`.

## Interview
- **STEPS:** parse program scope + rules (XSS-pinned) → XSS-scoped recon → `xss-context` feeder → fan the
  four variants (gated + reviewed, depth-first) → escalate/chain → triage/de-dupe → package submissions → review.
- **TOOLS:** the XSS family (`xss-context` + `xss-reflected`/`xss-stored`/`xss-dom`/`xss-blind`) +
  `js-analysis`, `attack-chain-discovery`, `reporting`; spine = `xss-context/refs/hunt_flow.md`;
  `_contract/{hunter-base,roe-gate}.md`.
- **GOAL:** Run an authorized XSS-only hunt end-to-end, strictly in scope, producing only VERIFIED,
  in-scope, non-duplicate XSS findings packaged as submission-ready reports. Done = checklist `- [x]`,
  review passes.
- **OUTPUT:** `program_scope.json`, `hunt_plan.md`, `submissions/`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = program scope/rules (link/text) → `scope.yaml`. Spine =
  `xss-context/refs/hunt_flow.md` (methodology + targeting + escalation catalog). Orchestrates Tier-1
  `js-analysis`, the XSS family, `attack-chain-discovery`, `reporting`. Contract = `_contract/hunter-base.md`.
- **DECOMPOSITION:** n/a (mission orchestrator).

## Goal
Deliver verified, in-scope, de-duplicated XSS submissions.
DONE = `checklist.md` `- [x]` · `review.md` PASS (scope parsed, plan + accepted-only submissions produced).

## Class block (the thin ~20%; steps 0–7, outputs + safety are `_contract/hunter-base.md`)
- **class:** XSS (reflected / stored / dom / blind).
- **recon surface:** `redstrike-js-analysis` (DOM sources/sinks, endpoints, params) + content/param
  discovery for reflected + stored surfaces (headers, JSON keys, upload/filename, profile/comment fields).
- **feeder:** `redstrike-xss-context` → `xss_context.json` (candidate points × reflection/context/CSP +
  DOM source→sink flows + per-point variant routing).
- **executors:** `redstrike-xss-reflected`, `redstrike-xss-stored`, `redstrike-xss-dom`,
  `redstrike-xss-blind` — each mechanical-gated + its `*-verify` reviewer; only `accepted` advance.
- **escalation ref:** `xss-context/refs/hunt_flow.md` — end-to-end flow, target prioritization, the XSS
  escalation catalog (earn the severity), and the not-Critical-without-terminal-impact rule.
- **class chains:** reflected + cache-poisoning → CDN-scale persistent XSS; self-XSS + CSRF → stored → ATO;
  DOM-on-OAuth-callback → token capture → ATO; SVG/upload → same-origin cookie theft; postMessage →
  cross-origin exfil; stored → privileged viewer → cross-priv. Compose via `redstrike-attack-chain-discovery`.

## Pipeline
Runs the `_contract/hunter-base.md` pipeline with the class block above: scope → XSS recon →
`xss-context` → the four variants (gated + reviewed, depth-first) → escalate/chain (`hunt_flow.md`
catalog + `attack-chain-discovery`) → triage/de-dupe → package (`reporting` + per-finding drafts in
`submissions/`, each meeting `bug-bounty/refs/report_quality.md`).

## Inputs
- program scope/rules (link/text), `scope.yaml`, `js-analysis` + `xss-context` + variant outputs
- `xss-context/refs/hunt_flow.md` (methodology spine), `_contract/hunter-base.md`

## Outputs
`program_scope.json` · `hunt_plan.md` · `submissions/` · `summary.md` · `logs/`

## Phases
- **Phase 1:** XSS-pinned scope parse + recon + `xss-context` feeder + prioritization.
- **Phase 2:** gated variant hunt (depth-first) + chaining + triage/de-dupe + submission packaging.

## Safety
Inherits `_contract/hunter-base.md` §Safety: strict program scope + rules; only submit `accepted`,
in-scope, non-duplicate findings; submissions are DRAFTS a human sends; stored-XSS payloads that can
reach real users stay benign + approval-gated + logged for cleanup (the variants enforce this);
scope-gate + audit everything. Zero accepted findings is a valid PASS (empty `submissions/` + a
`summary.md` saying so).
