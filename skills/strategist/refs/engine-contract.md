# `hunt_plan.json` — the engine-consumed contract (match EXACTLY)

The orchestrator's resume/`continue_prompt` loop and the concurrent wave-batcher consume `hunt_plan.json`
to decide **what order** classes are hunted in, **how deep** each wave goes, and **which classes get a
second differently-seeded pass**. They read exactly three per-class values, so every queue entry MUST
carry all three on every (re-)emit — no missing keys, no fallback guessing:

| Concept        | Where the engine reads it                     | Type / values                         | Meaning for the loop |
|----------------|-----------------------------------------------|---------------------------------------|----------------------|
| **rank**       | `queue[i].rank`                               | int, `>= 1`, **lower = hunted sooner**| the order the pending-class loop iterates; also the order waves are batched in |
| **depth_budget** | `queue[i].depth_budget.tier`                | `"floor"` \| `"standard"` \| `"deep"` | how much breadth ABOVE the escalation floor the executor spends (floor = ladder only; deep = ladder + a diversity pass) |
| **diversity_pass** | `queue[i].depth_budget.diversity_pass`    | bool                                  | whether the wave batcher schedules a second, differently-seeded pass (a cheap recall boost; typically `true` for `deep`) |

## Why the keys are nested, not flat

`depth_budget` and `diversity_pass` live **inside** the `depth_budget` object (not as flat entry keys)
because that is the shape `skills/_contract/hunt_plan.schema.json` defines and `scripts/validate.py` +
`scripts/tests/test_strategist.py` enforce (`additionalProperties:false` on both the entry and the
`depth_budget` object — a flat `diversity_pass` on the entry, or a scalar `depth_budget`, would FAIL the
schema). So the canonical access the engine uses is:

```python
for e in sorted(hunt_plan["queue"], key=lambda e: e["rank"]):      # rank — ascending
    tier       = e["depth_budget"]["tier"]                          # depth_budget — floor/standard/deep
    diversity  = bool(e["depth_budget"].get("diversity_pass", False))  # diversity_pass — bool
    steps      = int(e["depth_budget"].get("min_ladder_steps", 0))  # optional depth hint
```

## The strategist's obligation

- Emit **every pending (and, on re-rank, not-yet-`done`) class** as a queue entry.
- Give each entry's `depth_budget` **all three** of `tier`, `diversity_pass` (an explicit `true`/`false`,
  never omitted), and `min_ladder_steps` — so the engine never hits a missing key and never has to invent a
  default.
- A `floor` tier always means **run the full escalation ladder and nothing extra** — never below it. The
  budget only ever ADDS effort; it can never lower the deterministic recall floor (see the ABSOLUTE
  INVARIANT in `SKILL.md`).

## Session-dependence front-load (optional ordering input)

When the engagement's live web user session is dead/expiring, the strategist reorders the queue so every
session-**independent** class (`rank`s) ahead of every session-**dependent** one, and tags each dependent
entry `needs: ["fresh-session"]`. The engine reads this exactly like any other ordering:

- It still iterates the queue in ascending `rank` — the front-load IS the ordering, nothing special to do.
- `queue[i].needs` (optional; `["fresh-session"]`) is an **operator-facing annotation, not a gate**: the
  class is still `pending`, still owed in full, and still runs the moment a session returns. The engine
  **surfaces** these classes to the operator ("awaiting a fresh session — re-capture: `redstrike session
  import <eng> …`") instead of silently burning authed leads into a dead token — but it NEVER drops or
  skips them. `queue[i].session_dependence` and the root `session_state` are informational/audit only.
- Absent `needs` / `session_state`, or `session_state.status` live/unknown ⇒ behave exactly as before.

## Degraded / missing plan

If `hunt_plan.json` is absent or stale, the engine falls back to coverage-map order and treats every class
as `floor` with `diversity_pass=false`. That is recall-safe (every class is still routed and still owes the
full ladder) — the plan only optimizes ORDER and DEPTH on top of that floor. A missing or `unknown` session
signal is likewise recall-safe: it simply means no front-load this pass (rank on value alone).
