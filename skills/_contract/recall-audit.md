# recall-audit — the third altitude: "what did we miss?"

Redstrike's two existing review altitudes both face toward **precision**:

| altitude | question | catches |
|---|---|---|
| `review.md` (mechanical) | did every step run and emit well-formed output? | execution false-**negatives** (silent/empty step) |
| `verify.md` (semantic, the `*-verify` agents) | is each **reported** finding real, in-scope, rated right? | analytical false-**positives** (hallucinated vuln) |
| **`recall-audit` (this)** | **what should have been found but wasn't?** | **analytical false-NEGATIVES (missed findings)** |

`review.md` only proves a step *ran*; `verify.md` only looks at findings that *exist*. Neither asks whether
a class that cleared actually looked hard enough, or whether a skipped/never-run route was wrongly dropped.
That blind spot is where recall leaks — and why the framework, left alone, drifts toward "clean report, half
the surface untested" (the juice-shop-2026-10-20 engagement). This altitude closes it.

## How it runs
Engagement-level, once, **before reporting**, after the hunt and the per-finding verifiers — by the
independent **`recall-audit` reviewer agent** (`.claude/agents/recall-audit.md`) in a fresh context.

1. **Deterministic engine** — `python scripts/recall_audit.py <engagement>` ranks recall gaps the other
   gates don't catch, folding in the escalation ladder (`escalation.md`):
   - `shallow-clear` — a class ran, found nothing, but recon **signalled** the surface applies AND the
     escalation ladder is unexhausted → the clear is not yet trustworthy.
   - `skipped-but-signalled` — a class was skipped/`n/a` although an available recon signal matches its
     routing triggers → a route wrongly dropped.
   - `weak-skip-reason` — skipped with a missing/too-terse reason.
   - `pending-at-close` — a routed class never ran (also the coverage gate's domain; repeated for a
     self-contained recall report).
   - `un-reconverged` — run `python scripts/reconverge.py --validate <engagement>`: an un-converged
     re-convergence inbox (`reconvergence.md`) means surface discovered DURING the hunt (an internal host,
     a new identity, a leaked API base-url) was never routed back → a REAL-MISS to adjudicate.
2. **Adjudication** — the reviewer classifies each gap from the evidence as **REAL-MISS** /
   **JUSTIFIED-CLEAR** / **BLOCKED (open-proof-gap)**, and sanity-checks for an unconsumed recon signal.
3. **Record** — `reviews/recall_audit.verdict.json`.

## The rule it enforces
A **REAL-MISS** must be re-hunted (run the next escalation step, or un-skip the route) or explicitly
accepted by the operator with a recorded reason **before reporting**. A report may not ship over an
unadjudicated recall gap. Low-prior empties (no recon signal) are acceptable clears — this altitude does
not manufacture work on surfaces recon found no reason to test.

## Relationship to the other gates
- [`coverage.md`/`coverage.py`] proves categories are **accounted for** (nothing silently `pending`).
- [`escalation.md`] gives the executor the **ladder** so an empty high-prior surface isn't closed early.
- **recall-audit** is the independent reviewer that checks the first two actually happened — that an
  "accounted-for-as-clear" result is a *real* clear, not a shallow one. It is to false negatives what the
  `*-verify` gauntlet is to false positives.
