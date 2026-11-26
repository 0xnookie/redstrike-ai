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
  reachable CVEs) + the session-liveness signal (`runtime/session_status.json` / `redstrike session
  status`) and each class's `session_dependence` → score each `pending` class → rank into a hunt queue
  (front-loading session-independent classes + annotating the dependent queue `needs: fresh-session` when
  the session is dead/expiring) → assign a depth budget bounded BELOW by the escalation floor → write
  rationale per class → emit `hunt_plan.json` → review. On re-invocation: read the findings so far + the
  current plan + the current session liveness, drop `done` classes, re-score and re-rank only the
  REMAINING queue (incremented `iteration`).
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
  `notebook.json`, `cve_intel.json`, `scope.yaml`, `routing-map.json` (`session_dependence`), the
  OPTIONAL `runtime/session_status.json` session-liveness signal, and (on re-rank) the engagement
  findings. Chains FROM the recon feeders + coverage/surface ledgers + the session-liveness signal;
  chains TO the orchestrator (ordering) and, via the depth-budget, to the executors + `parameter-optimization`.
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

## Engine contract — the keys the hunt pool reads (match EXACTLY)
The orchestrator's resume / `continue_prompt` loop and the concurrent **wave-batcher** consume
`hunt_plan.json` and read exactly three per-class values, so EVERY queue entry MUST carry all three on
every (re-)emit — no missing keys, no fallback guessing (full table + the access snippet live in
`refs/engine-contract.md`):
- **`rank`** (`queue[i].rank`) — int, `>= 1`, **lower = hunted sooner**; it orders both the pending-class
  loop and the order waves are batched in.
- **`depth_budget`** (`queue[i].depth_budget.tier`) — `floor` \| `standard` \| `deep`; how much breadth
  ABOVE the escalation floor each wave spends.
- **`diversity_pass`** (`queue[i].depth_budget.diversity_pass`) — bool; whether the wave-batcher schedules
  a second, differently-seeded pass (a cheap recall boost; typically `true` for `deep`).

These two budget keys are **nested inside the `depth_budget` object** (not flat entry keys) because that is
the shape `skills/_contract/hunt_plan.schema.json` defines and `scripts/validate.py` enforces
(`additionalProperties:false` closes both the entry and `depth_budget`). Give every entry's `depth_budget`
**all of** `tier`, an EXPLICIT `diversity_pass` (`true`/`false`, never omitted), and `min_ladder_steps`, so
the engine reads `rank` / `depth_budget.tier` / `depth_budget.diversity_pass` on every class without ever
hitting a missing key. If `hunt_plan.json` is absent/stale the engine falls back to coverage-map order with
every class at `floor` + `diversity_pass=false` — recall-safe, because the floor is still owed in full.

## Ranking inputs (how a class is scored — all read-only)
Combine, per `pending` class (none of these may ever *remove* a class or lower its floor):
1. **Recon prior** — did recon signal this class's surface as a real candidate? (high/unknown/low;
   unknown is treated as high, matching the recall-safe default.)
2. **Surface breadth** — how many `surface_ledger.json` elements route to the class (more surface ⇒
   more to test ⇒ usually higher).
3. **CVE intel** — a version-matched, reachable CVE on a component the class covers (`cve_intel.json`)
   is a strong boost and typically warrants `deep`. The cached CVE knowledge base `cve_kb.jsonl`
   (cve-intelligence's cache-once, retrieve-many corpus) is the same intel's durable, offline-capable
   form — a read-only retrieval input you may consult when `cve_intel.json` is thin or stale. When such
   a CVE also carries a `technique_seed` (a technique-class first-probe hint), that is a further signal
   the class has a concrete, evidenced first benign probe ready — rank it sooner so the executor reaches
   the seeded probe early.
4. **Feeder richness** — how much the class's `<class>_context.json` found (confirmed reflections,
   injectable params, object refs, URL-fetch sinks, auth flows).
5. **Notebook leads** — open/promoted leads in `notebook.json` pointing at the class.
6. **Severity ceiling** — the worst plausible impact if it lands (a ranking input, never a report cap).
7. **Chaining potential** (re-rank) — an accepted finding that could compose with this class raises it.
8. **Session dependence × session liveness** — each class's `session_dependence` (from `routing-map.json`:
   `independent` / `dependent` / `mixed`) crossed with the engagement's live web-session liveness
   (`runtime/session_status.json` / `redstrike session status`). When the session is DEAD/EXPIRING this
   becomes a **dominant ordering key** (see "Session-dependence-aware ordering"): session-independent
   classes rank first, session-dependent ones fall to the back of the queue with a `needs: fresh-session`
   annotation. When the session is live/unknown/absent it has NO effect (rank on value alone).

## Steps  (action · tool · output)
1. Load the post-recon state (coverage + surface ledgers, `*_context.json`, notebook, cve_intel, scope) · read/JSON · (in memory); record what was read in `inputs_seen`
2. Select the classes to rank = every `pending` (and, on re-rank, not-yet-`done`) category in the coverage ledger · filter · (in memory)
3. Consult session liveness (`runtime/session_status.json` / `redstrike session status`) + read each class's `session_dependence` from `routing-map.json`; classify the aggregate (live/expiring/expired/dead/unknown) and record it in `session_state` · read/JSON · (in memory)
4. Score each selected class from the ranking inputs above · reasoning · `logs/scoring.md`
5. For each class, read its escalation-ladder floor (`scripts/escalation.py` ladder_for) and assign a depth budget AT OR ABOVE that floor (`floor`/`standard`/`deep`) · escalation.py (read-only) · (in memory)
6. Rank into a queue (ascending `rank` = hunt order) with a per-class `rationale`; when the session is expiring/expired/dead, front-load `independent` classes ahead of `dependent` ones and annotate each `dependent` entry `needs: ["fresh-session"]` (ORDER + annotation only — never a skip/drop) · synth · `hunt_plan.json`
7. Emit `hunt_plan.json` conforming to `skills/_contract/hunt_plan.schema.json` — every queue entry carries `rank` + a `depth_budget` with `tier` + an explicit `diversity_pass` + `min_ladder_steps` (the exact keys the engine reads — see "Engine contract" / `refs/engine-contract.md`); `ledger_owner` stays `coverage.py`; no `skipped` state; no ledger touched · write/JSON · `hunt_plan.json`
8. Emit summary · synth · `summary.md`
9. /REVIEW SKILL · `review.md`

## Re-invocation (re-rank the remaining queue)
On a later call: read the current `hunt_plan.json` + the engagement findings, mark hunted classes
`done`, increment `iteration`, re-score the REMAINING classes (now weighting chaining potential from
accepted findings), and re-emit. It never resurrects a `done` class's coverage obligation or changes
the ledger — it only re-orders what is still queued.

**Re-ranking after the exhaustion adversary.** When the cross-model `exhaustion-adversary` (redstrike SKILL
§3.5) returns `found_gaps` at pre-report, `coverage.py` re-opens the categories those gaps name and the
orchestrator re-drives them. If you are re-invoked at that point, treat each adversary `found_gap`'s
category as a high-priority re-opened class and rank it to the FRONT of the remaining queue (with a
depth-budget at least as deep as the gap's remediation implies) — so the re-drive hits the named gap first.
You still never skip a class or lower the floor; you only re-order the re-opened work.

## Session-dependence-aware ordering (dead-session reorder — ORDER + ANNOTATION only)
The real failure this guards against: a short-lived (~1h) web user token expires mid-run, and the
orchestrator keeps burning AUTHED leads into a dead token while **session-INDEPENDENT** classes
(JWT/auth-forge — you forge a token, you never reuse the live one; recon; CVE; and every unauthenticated
web class) could have run fine. Nothing reordered the hunt around the dead session. The strategist fixes
that **purely by ordering** — it never drops, skips, or lowers the floor of a single class.

**The two inputs (both read-only).**
- **Per-class `session_dependence`** from `routing-map.json` (`queue[i].class` → that category's field):
  - `independent` — runs fine with a dead/expiring session (unauthenticated probing, or it forges/bypasses
    its own session): jwt/auth-forge, cve-intelligence, exposed-surface, security-headers, tls, cors,
    clickjacking, open-redirect, crlf, cache-poisoning, host-header, subdomain-takeover, secrets,
    forbidden-bypass, request-smuggling, supply-chain, code-audit, the framework/CVE classes, and host/
    content/js recon (recon feeders run pre-hunt anyway).
  - `dependent` — needs a LIVE authenticated user session: authz (idor/privesc), api (bola-bfla/graphql),
    file (path-traversal/upload-rce), business-logic, race-condition, browser-exploit (and mass-assignment,
    which lives inside idor/bola-bfla).
  - `mixed` / **absent** — some sub-techniques need a session and some do not (xss, sqli, injection, ssrf,
    xxe, nosql/ldap/prototype/parameter-pollution, crypto, email, websocket, …). **Treated as unknown:
    never force-front-loaded, never annotated.** A category with no `session_dependence` key is `mixed` by
    default (backward-compatible — an un-annotated map still ranks exactly as before).
- **Session liveness** = the aggregate of the engagement's stored web identities, from
  `<engagement>/runtime/session_status.json` (if present) or the `redstrike session status` result
  (exit 1 ⇒ an identity needs re-capture). Classify as `live` / `expiring` / `expired` / `dead` /
  `unknown`. **Record what you consulted in the plan's `session_state`** (`status`, `source`,
  `needs_recapture`, `checked_at`) so the reorder is auditable — WHY the independent classes were
  front-loaded this pass.

**The ordering rule.**
- **Session `live` / `unknown` / signal ABSENT ⇒ do nothing differently.** Rank on value alone (inputs
  1–7). `unknown`/absent is treated as live so a missing or opaque-session signal can NEVER block or
  shrink the hunt (recall-safe default). Emit no `needs` annotations.
- **Session `expiring` / `expired` / `dead` ⇒ front-load the session-independent work.** Partition the
  remaining queue into `independent` → `mixed`/absent → `dependent`, and assign `rank` so that **every
  `independent` class ranks ahead of every `dependent` class** (ties inside a band broken by the normal
  value score). Give each `dependent` entry `needs: ["fresh-session"]` — it is **surfaced to the operator
  as "awaiting a fresh session", NOT skipped**: its `queue_state` stays `queued` (or `deferred`), it still
  owes the full escalation ladder, and it runs in full the moment a session returns. `mixed`/absent
  classes keep their value rank between the two bands (they can still make progress on unauthenticated
  surface, so they are neither front-loaded as guaranteed-safe nor annotated).

**This is reorder + annotation ONLY — it honors the ABSOLUTE INVARIANT above.** A dead session NEVER:
removes a class from the queue, marks it `skipped`, writes a ledger, or lowers any recall floor. Every
`dependent` class is still routed in `coverage_ledger.json` and still owed in full; if it never runs
because the session never came back, it surfaces as a normal `pending`/shallow-clear and is caught by the
§2c coverage gate + §2d recall audit before any report ships — exactly as if the strategist had never run.
`needs: fresh-session` is an operator-facing annotation, not a coverage status.

**Re-rank when the session changes.** On a re-invocation after a fresh session is captured (session back to
`live`), drop the `needs: fresh-session` annotations and re-rank the remaining queue on value alone — the
previously-deferred dependent classes return to normal priority. (Symmetrically, a session that dies
mid-run re-triggers the front-load on the next re-rank.)

## Tools
- File I/O + JSON only (no network, no target traffic).
- `scripts/escalation.py` — READ-ONLY, to read each class's ladder floor so a depth budget can't fall below it.

## Inputs
- `coverage_ledger.json` (routed classes), `surface_ledger.json` (surface breadth), the `*_context.json`
  feeders (sink richness), `notebook.json` (leads), `cve_intel.json` (CVE matches) + optionally
  `cve_kb.jsonl` (the cached CVE corpus, as a read-only retrieval input), `scope.yaml`, and —
  on re-rank — the engagement findings (`<eng>/*/findings.json` or `findings.json`).
- `routing-map.json` per-class `session_dependence` (independent/dependent/mixed) + the session-liveness
  signal `<engagement>/runtime/session_status.json` (OPTIONAL — or the `redstrike session status` result);
  both read-only. Absent ⇒ `mixed`/live default (no reorder). Drives the dead-session front-load above.

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
them. A mis-ranked plan wastes budget at worst — it can never cause a silent miss. The **dead-session
front-load** is the same thing: a `needs: fresh-session` annotation + a reorder, never a drop — every
session-dependent class stays `pending` and owed in full, so it is re-driven when the session returns and
caught by the coverage + recall gates if it is not.
