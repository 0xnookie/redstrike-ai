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

This is no longer advisory. Once `report/findings_consolidated.json` exists, `verify_completion.py
--engagement` runs the deterministic engine and **HARD-FAILS** on any `shallow-clear`,
`skipped-but-signalled`, or `never-run`/`pending-at-close` gap (the noxframe report shipped over ~10 HIGH
shallow-clear gaps — exactly this). Clear a gap by escalating + re-running the class, **or**, for a gap that
is genuinely unclosable in this environment, record an honest accept.

### Re-affirming an already-worked class — `--reaffirm`, not a copied note
To re-assert a class you genuinely worked (a later wave re-touches it, or the recall engine re-flags a clear
you already substantiated), use **`python scripts/coverage.py --reaffirm <class> --engagement <dir>`**
(`--subsurface <leg>` for a family leg). It recomputes `depth_substantiated` PURELY from the depth payload
already retained on the ledger entry and refreshes it with **no new free-text note** — succeeding when that
payload substantiates the clear, refusing with the specific gap otherwise. This replaces the copy-paste-note
loop (re-running `--mark <class> --status attempted --depth-note "<the same note again>"` to re-affirm),
which trips the oversight/duplication classifier. `--reaffirm` never invents a note, so it cannot fabricate a
clear — an un-substantiated entry is refused, not stamped.

### Honest-accept — the first-choice close for a genuinely-unclosable gap
Do **not** hand-fake a clear (`coverage.py --mark <class> --status attempted --count 0 --escalations <full
ladder>` deterministically clears a shallow-clear with no reason — the fabrication the safety classifier
blocks). Record the accept with the writer instead, which is un-gameable:

```
python scripts/recall_audit.py --accept <type:category> --engagement <dir> \
    --blocker <csv> [--ladder-run <csv>] --reason "<why this gap is unclosable here>"
```

- **`--blocker` is REQUIRED**, from a CLOSED vocabulary (`no-oob-collaborator`, `single-identity`,
  `browser-declined`, `captcha-gated`, `opaque-session`, `no-sink-surface`, `destructive-withheld`,
  `no-mailbox`). An accept must NAME the environmental reason the gap couldn't be closed — it states
  "couldn't, **because X**" (auditable), never "tried, trust us".
- The writer **refuses** an accept for a `(type:category)` the deterministic engine does not currently
  flag (no pre-stamping non-gaps), and for a `shallow-clear` it **requires `--ladder-run`** — the real
  escalation technique ids that genuinely ran (validated against the class's ladder), recorded separately
  from the residual blocker.
- It writes `reviews/recall_audit_accepts.json` in the list shape the gate already reads
  (`[{"id":"<type>:<category>", "reason":..., "blocker":[...], "ladder_run":[...]}]`). A bare `"<category>"`
  id accepts all of that class's gated gaps. An accepted gap is surfaced as a **warning**, never a silent pass.

> Orchestration: run **`python scripts/close.py --engagement <dir>`** before `verify_completion.py` so the
> diagnostics gate always reads a current run record for this engagement (fresh or historical), then clear or
> accept each recall gap, then re-run the gate.

## Relationship to the other gates
- [`coverage.md`/`coverage.py`] proves categories are **accounted for** (nothing silently `pending`).
- [`escalation.md`] gives the executor the **ladder** so an empty high-prior surface isn't closed early.
- **recall-audit** is the independent reviewer that checks the first two actually happened — that an
  "accounted-for-as-clear" result is a *real* clear, not a shallow one. It is to false negatives what the
  `*-verify` gauntlet is to false positives.
