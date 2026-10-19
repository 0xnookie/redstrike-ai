# hunter-base — the single-class hunter contract (inherited by every `*-hunter`)

A **single-class hunter** (`<class>-hunter`, e.g. `xss-hunter`) is a Tier-3 MISSION agent that drives
the whole pipeline toward ONE vuln class, depth-first. It is `bug-bounty` with the routing pinned to
one class — SAME machinery, narrower scope, deeper iteration. It **reuses** the shared stages (it does
NOT re-implement them): the class's `<class>-context` feeder, the class's executors + their `*-verify`
reviewers, and `reporting` / `report_quality.md` packaging. It emits **no findings of its own** →
`review.md` only, no `verify.md` (the executors' reviewers verified every finding).

## When a hunter vs the general bug-bounty agent
- **bug-bounty** = breadth-first across ALL classes (recon → route per `vuln-catalog.md` → everything).
- **a hunter**  = depth-first on ONE class — point it at a target, spend the whole budget on that class
  (more surfaces, more ladder rungs, more escalation), return submission-ready findings.

Use a hunter when the operator wants to hunt a single class; use bug-bounty for a full program sweep.
Both reuse the same feeders, executors, reviewers, and packaging — **a hunter is a thin wrapper**, not a
fork. (A hunter never duplicates an executor or a reviewer; if two hunters would share recon, that recon
stays in the Tier-1 skill.)

## The shared pipeline (every hunter runs this; only the CLASS BLOCK changes)
0. **Authorization + scope** — `_contract/roe-gate.md`. If launched by the `redstrike` CLI with a filled
   `scope.yaml` + `runtime/authorization.json`, intake is DONE (don't re-ask); else STOP until scope is
   set. Pin scope to the class: only the class's surface is in play; honor program exclusions + rate limits.
1. **Scope + plan** → `program_scope.json` + `scope.yaml`; a class-pinned `hunt_plan.md` (targets × the
   class's surface, prioritized).
2. **Class-scoped recon** — only the recon the class needs (the CLASS BLOCK names it), not a full sweep.
3. **Feeder** — run the class's `<class>-context` → `<class>_context.json` (the shared analysis the
   executors fan out from).
4. **Gated hunt (depth-first)** — run the class's executors; each mechanical-gated
   (`verify_completion.py`) then its `*-verify` reviewer subagent. **Only `accepted` findings advance.**
   Iterate for DEPTH within budget (the class's ladders/surfaces), not breadth across other classes.
5. **Escalate** — the class's escalation catalog (the CLASS BLOCK's escalation ref) + `attack-chain-
   discovery` for cross-finding composites. Rate to the impact actually demonstrated
   (`severity-calibration.md`).
6. **Triage / de-dupe** — drop duplicates (program known issues + internal); keep `accepted` + in-scope +
   non-duplicate only.
7. **Package** — `reporting` + per-finding submission drafts in `submissions/`, each meeting
   `bug-bounty/refs/report_quality.md`. Submitting is outward-facing → DRAFTS a human sends.

## What a per-hunter `SKILL.md` MUST specify (the thin CLASS BLOCK — the only ~20% that differs)
- **class** — the vuln class this hunter owns.
- **recon surface** — the Tier-1 recon that matters for the class (XSS → `js-analysis` DOM sinks +
  param/stored-surface discovery; SQLi → param discovery + error/response surfacing; etc.).
- **feeder** — the `<class>-context` skill + its context artifact.
- **executors** — the exact executor set (each already gated + reviewed).
- **escalation ref** — the class's hunt-flow / escalation catalog (methodology + chains + severity rule).
- **class chains** — the class-specific escalation patterns worth pursuing.

Everything else (steps 0–7, outputs, safety) is inherited from here — keep each `*-hunter` thin.

## Shared outputs (same shape as bug-bounty, so `status` / `verify` tooling is uniform)
`program_scope.json` · `hunt_plan.md` · `submissions/` · `summary.md` · `logs/`

## Safety
A hunter is as STRICT as bug-bounty: pin to the program's scope + rules absolutely; only submit
`accepted`, in-scope, non-duplicate findings; submissions are DRAFTS a human sends; exploitation and
anything past benign confirmation is approval-gated (`roe-gate.md`); everything is scope-gated +
audit-logged. An engagement with zero accepted findings is a valid outcome (empty `submissions/` + a
`summary.md` saying so) — never fabricate a finding to fill the hunt.
