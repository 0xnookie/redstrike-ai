# Bug Bounty Agent

> TIER-3 MISSION agent (see `_contract/agent-tiers.md`) — a goal-driven entry point that orchestrates
> Tiers 1–2 toward a bug-bounty program. Owns the program's (often stricter) scope + rules.
> Drives other skills; findings come from the gated vuln agents (each with its own reviewer) →
> this skill emits NO findings of its own → `review.md` only, no `verify.md`.

## Interview
- **STEPS:** parse program scope + rules → recon → prioritize targets → run the matching vuln agents (gated + reviewed) → chain → triage/de-dupe → package submission-ready reports → review.
- **TOOLS:** the Redstrike skill set (orchestrated) + `reporting`; `_contract/roe-gate.md` fed by the program scope.
- **GOAL:** Run an authorized bug-bounty engagement end-to-end, strictly within the program's scope + rules, producing only VERIFIED, in-scope, non-duplicate findings packaged as submission-ready reports. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `program_scope.json`, `hunt_plan.md`, `submissions/`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = the program's scope/rules (link or text) → `scope.yaml`. Orchestrates Tier-1 (`js-analysis`), Tier-2 (all vuln agents), `cve-intelligence`, `attack-chain-discovery`, `reporting`.
- **DECOMPOSITION:** n/a (mission orchestrator).

## Goal
Deliver verified, in-scope, de-duplicated bug-bounty submissions.
DONE = `checklist.md` `- [x]` · `review.md` PASS (scope parsed, plan + accepted-only submissions produced).

## Orchestration
1. **Program scope + rules** → `program_scope.json` + fill `scope.yaml` (in/out scope, allowed classes, NO-DoS / no-social-eng / rate limits per the program). Nothing runs out of program scope.
2. **Recon** — `redstrike-js-analysis` (+ discovery). **Prioritize** targets/classes with `redstrike-cve-intelligence` + the program's focus → `hunt_plan.md`.
3. **Hunt** — run the applicable `redstrike-<vuln>` skills, each gated (mechanical → its reviewer subagent). Only `accepted` findings advance.
4. **Chain** — `redstrike-attack-chain-discovery` for higher-impact composites.
5. **Triage/de-dupe** — drop duplicates (program's known issues / internal dupes); keep only `accepted`, in-scope, non-dup findings.
6. **Package** — `redstrike-reporting` + per-finding submission drafts in `submissions/` (program's format: title, severity, steps, impact, remediation).

## Inputs
- program scope/rules (link/text), `scope.yaml`, `js-analysis` + vuln-agent outputs

## Outputs
`program_scope.json` · `hunt_plan.md` · `submissions/` · `summary.md` · `logs/`

## Phases
- **Phase 1:** scope parse + recon + prioritization.
- **Phase 2:** gated hunt + chaining + triage/de-dupe + submission packaging.

## Safety
Bug-bounty programs are STRICTER than pentests — enforce the program's scope + rules absolutely
(in-scope assets only; honor exclusions: no DoS, no social engineering, no disallowed automated
scanning; obey rate limits). **Only submit `accepted`, in-scope, non-duplicate findings.** Submitting is
outward-facing — draft the submission; a human sends it. Scope-gate everything; audit-log.
