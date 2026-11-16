---
name: strategist
description: Run the Redstrike strategist / hunt-planner capability — read the post-recon state (coverage_ledger.json, surface_ledger.json, the *_context.json feeders, notebook.json, cve_intel.json) and emit a ranked hunt_plan.json (hunt queue + per-class depth budget + rationale) that ORDERS the orchestrator's pending-class loop. Re-invokable to re-rank the REMAINING queue as findings arrive. Tier-3 capability skill (review.md only, emits NO findings, writes NO ledger). ORDER + DEPTH-BUDGET only — it can never skip a class or lower the recall floor.
---

> TIER-3 CAPABILITY agent (see `_contract/agent-tiers.md`). A shared PLANNING SERVICE: reads the
> post-recon engagement state and emits a ranked hunt queue + per-class depth budget the orchestrator
> consumes to ORDER its pending-class loop. Emits NO findings → `review.md` only, no `verify.md`,
> no reviewer. It is a thin wrapper over existing state — it re-ranks, it does not re-derive recon.

## ABSOLUTE INVARIANT — read this first (the whole point of the skill)
The strategist controls **ONLY two things: the ORDER classes are hunted in, and the per-class
DEPTH-BUDGET** (how much effort ABOVE the mandatory escalation floor each class is worth). It is a
ranking artifact, not a control plane. In particular it **MUST NEVER**:
- mark any class `skipped` (or `n/a`, or any coverage status). `hunt_plan.json` has no `skipped`
  queue-state — only `coverage.py` may record a skip, and only with a reason.
- write `coverage_ledger.json`, `surface_ledger.json`, or **any** ledger. **`coverage.py` stays the
  SOLE ledger owner.** The strategist reads ledgers; it never patches them.
- **lower the deterministic recall floor.** The depth-budget can only ADD effort, never remove it.
  Even the lowest budget tier (`floor`) means "exhaust the full escalation ladder and no more" — it
  does **not** mean "do less than the ladder". The floor (`escalation.py` + `verify-base.md` check #5
  + the `recall-audit` gate) is unconditional and outside the strategist's control.

**Why this is safe:** if the strategist mis-ranks a real class low, or gives it only `floor` budget,
that class is still **routed** in the coverage ledger and still owes the full escalation ladder. An
under-hunted class therefore still surfaces as a **shallow-clear** and is caught by the existing
recall gate before any report ships. The worst a bad plan can do is change the ORDER work happens in
and waste budget — it can never create a silent miss. Ranking is an optimization on top of a
recall-safe floor, never a replacement for it.

## Interview
- **STEPS:** read the post-recon state (coverage ledger = what's routed, surface ledger = how much
  surface, the `*_context.json` feeders = sink richness, notebook = leads, cve_intel = version-matched
  reachable CVEs) → score each `pending` class → rank into a hunt queue → assign a depth budget bounded
  BELOW by the escalation floor → write rationale per class → emit `hunt_plan.json` → review. On
  re-invocation: read the findings so far + the current plan, drop `done` classes, re-score and re-rank
  only the REMAINING queue (incremented `iteration`).
- **TOOLS:** none beyond file I/O + JSON — this is PURE reasoning over on-disk state (no network, no
  target traffic). Reuses `scripts/escalation.py` (read-only) to know each class's ladder floor.
- **GOAL:** Produce a ranked `hunt_plan.json` the orchestrator consumes to order its pending-class
  loop, raising the chance that the highest-impact, most-evidenced classes are hunted first and
  budgeted deepest — WITHOUT ever changing WHICH classes run or how shallow any clear may be. Done =
  checklist `- [x]`, review passes.
- **WHEN:** right after `coverage.py --plan` (and `surface.py --plan`) build the ledgers, before the
  orchestrator starts the pending-class loop; then **re-invoke** after each wave of findings to re-rank
  the remaining queue (a confirmed finding can raise a related class for chaining, or let an exhausted
  class fall).
- **OUTPUT:** `hunt_plan.json` (schema `skills/_contract/hunt_plan.schema.json`), `summary.md`, `logs/`.
- **DATA / RAG:** inputs = `coverage_ledger.json`, `surface_ledger.json`, the `*_context.json` feeders,
  `notebook.json`, `cve_intel.json`, `scope.yaml`, and (on re-rank) the engagement findings. Chains
  FROM the recon feeders + coverage/surface ledgers; chains TO the orchestrator (ordering) and, via
  the depth-budget, to the executors + `parameter-optimization`.
- **DECOMPOSITION:** n/a (capability service).

## Goal
Emit a ranked, reviewable `hunt_plan.json` (hunt queue + per-class depth budget + rationale) that
orders the orchestrator's pending-class loop, and re-rank the remaining queue on re-invocation.
DONE = `checklist.md` `- [x]` · `review.md` PASS (`hunt_plan.json` present, valid vs the schema, every
routed `pending` class represented, no `skipped` state, no ledger written).

## What do we want
- **A ranked hunt queue** over the `pending` classes in `coverage_ledger.json` — highest expected
  value first — so the orchestrator spends its earliest, freshest budget where it matters most.
- **A per-class depth budget** (`floor` / `standard` / `deep`), bounded BELOW by the escalation ladder,
  that tells the executor how much breadth beyond the floor (proactive `parameter-optimization`,
  diversity passes) a class is worth.
- **A rationale per class** — the reviewable reasoning (priors, surface breadth, CVE matches, feeder
  richness, severity ceiling, chaining potential) that justifies the rank and budget.
- **Re-rankability** — a later pass re-scores the REMAINING queue from the findings that have landed.

## Ranking inputs (how a class is scored — all read-only)
Combine, per `pending` class (none of these may ever *remove* a class or lower its floor):
1. **Recon prior** — did recon signal this class's surface as a real candidate? (high/unknown/low;
   unknown is treated as high, matching the recall-safe default.)
2. **Surface breadth** — how many `surface_ledger.json` elements route to the class (more surface ⇒
   more to test ⇒ usually higher).
3. **CVE intel** — a version-matched, reachable CVE on a component the class covers (`cve_intel.json`)
   is a strong boost and typically warrants `deep`.
4. **Feeder richness** — how much the class's `<class>_context.json` found (confirmed reflections,
   injectable params, object refs, URL-fetch sinks, auth flows).
5. **Notebook leads** — open/promoted leads in `notebook.json` pointing at the class.
6. **Severity ceiling** — the worst plausible impact if it lands (a ranking input, never a report cap).
7. **Chaining potential** (re-rank) — an accepted finding that could compose with this class raises it.

## Steps  (action · tool · output)
1. Load the post-recon state (coverage + surface ledgers, `*_context.json`, notebook, cve_intel, scope) · read/JSON · (in memory); record what was read in `inputs_seen`
2. Select the classes to rank = every `pending` (and, on re-rank, not-yet-`done`) category in the coverage ledger · filter · (in memory)
3. Score each selected class from the ranking inputs above · reasoning · `logs/scoring.md`
4. For each class, read its escalation-ladder floor (`scripts/escalation.py` ladder_for) and assign a depth budget AT OR ABOVE that floor (`floor`/`standard`/`deep`) · escalation.py (read-only) · (in memory)
5. Rank into a queue (ascending `rank` = hunt order) with a per-class `rationale` · synth · `hunt_plan.json`
6. Emit `hunt_plan.json` conforming to `skills/_contract/hunt_plan.schema.json` (`ledger_owner` stays `coverage.py`; no `skipped` state; no ledger touched) · write/JSON · `hunt_plan.json`
7. Emit summary · synth · `summary.md`
8. /REVIEW SKILL · `review.md`

## Re-invocation (re-rank the remaining queue)
On a later call: read the current `hunt_plan.json` + the engagement findings, mark hunted classes
`done`, increment `iteration`, re-score the REMAINING classes (now weighting chaining potential from
accepted findings), and re-emit. It never resurrects a `done` class's coverage obligation or changes
the ledger — it only re-orders what is still queued.

## Tools
- File I/O + JSON only (no network, no target traffic).
- `scripts/escalation.py` — READ-ONLY, to read each class's ladder floor so a depth budget can't fall below it.

## Inputs
- `coverage_ledger.json` (routed classes), `surface_ledger.json` (surface breadth), the `*_context.json`
  feeders (sink richness), `notebook.json` (leads), `cve_intel.json` (CVE matches), `scope.yaml`, and —
  on re-rank — the engagement findings (`<eng>/*/findings.json` or `findings.json`).

## Outputs
`hunt_plan.json` (schema `skills/_contract/hunt_plan.schema.json`) · `summary.md` · `logs/`

## Phases
- **Phase 1 (generic):** load state + score each pending class from the ranking inputs.
- **Phase 2 (target-specific):** assign depth budgets at/above the escalation floor, rank, emit, re-rank.

## Safety
Read-only planning — the strategist sends no payload, touches no target, and changes no engagement
state. It is **scope-gated + audit-logged** like every skill, but it is the LEAST invasive skill in the
framework. Its single hard rule is the ABSOLUTE INVARIANT above: **order + depth-budget only; never a
skip, never a ledger write, never a lowered recall floor.** `coverage.py` owns the ledger; the
escalation ladder + the recall-audit gate own the floor; the strategist only orders the work on top of
them. A mis-ranked plan wastes budget at worst — it can never cause a silent miss.
