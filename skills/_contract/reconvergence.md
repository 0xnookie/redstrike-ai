# re-convergence — feed findings BACK into recon until a fixpoint

The recall fixes so far add breadth and depth **within what recon found at the start**: the coverage
ledger proves which classes ran, the surface ledger proves how much of the *recon-time* surface each was
tested against, the escalation ladder keeps an empty high-prior surface open. All of them assume the
attack surface is fixed after recon. It is not.

**Hunting discovers new surface.** An SSRF reaches an internal host or cloud metadata; a finding leaks an
API base-url, a vhost, a subdomain, or new parameters; an auth bypass yields the second identity IDOR/BOLA
needed; a config leak exposes endpoints recon never saw. In a single-pass pipeline (recon → plan → hunt →
report) none of that flows back — the newly-found surface is never routed to the executors that should
test it, and a run can reach `report` having never re-converged. That is the single-pass recall leak (the
juice-shop-2026-10-20 shape: terminate before closure, half the surface never routed).

## The rule
A finding that reveals a new **signal** or new **surface** RE-OPENS the classes that signal/surface now
routes to, and the engagement is **DONE only at the fixpoint** — a re-convergence pass that adds nothing
new. Re-convergence is to *discovered-during-the-hunt breadth* what the escalation ladder is to depth and
the surface ledger is to recon-time breadth.

## The loop (engagement-level; the orchestrator drives it)
1. **Emit** — when any executor discovers new surface/signal, it appends an observation to
   `<eng>/reconvergence/inbox.jsonl`, one JSON record per line:
   `{"source":"ssrf","signals":["asset:cloud","param:url-fetching"],
     "surface":[{"kind":"endpoint","value":"http://169.254.169.254/latest/meta-data/","discovered_by":"ssrf"}]}`
   (`signals` use the `routing-map.json` vocabulary; `surface.kind` ∈ the surface-ledger kinds.)
2. **Plan** — `python scripts/reconverge.py --plan --engagement <dir>` diffs the inbox against the two
   ledgers and reports: `added_signals`, `added_surface`, `reopen` (terminal classes to re-run), and
   `replan_candidates` (out-of-phase classes a new signal matched — an operator scope decision).
3. **Apply + re-hunt** — `reconverge.py --apply` flips the reopened classes back to `pending`, folds the
   new signals/surface into the ledgers, then the orchestrator runs those classes against the new surface.
   New discoveries append more inbox records.
4. **Repeat to the fixpoint** — `reconverge.py --validate` passes (exit 0) when a pass adds nothing new.

## Scope safety
A new signal only auto-reopens a class whose phase is **already active** (`attempted`/`skipped`). A signal
that matches an **out-of-phase** (`n/a`) class — e.g. `asset:smart-contract` implying the whole web3 phase —
is surfaced as a `replan_candidate`/`replan_phase` for the operator, **never auto-activated** (a new phase
is a scope decision). `blocked` classes are left for the operator too.

## Termination (why the loop always ends)
Each pass processes only the **delta** — signals/surface not already in the ledgers — and `--apply` folds
that delta in, so the seen-set grows monotonically and never shrinks. Signals come from a finite vocabulary
and discoverable surface is finite, so the delta empties after finitely many passes and `--validate` goes
green. `MAX_ROUNDS` is a safety bound against a misbehaving emitter, not a feature limit.

## Gate posture (incremental, like surface started)
Once a consolidated report exists **and** a non-empty `reconvergence/inbox.jsonl` exists,
`verify_completion.py --engagement` **hard-fails** while a pass still has un-routed signals/surface — a
report may not ship over mid-hunt discoveries that were never re-converged. No inbox ⇒ no gate
(re-convergence is opportunistic: a clean engagement that discovered no new surface simply has none).

## How it composes
- [`coverage.md`] accounts for every **class**; [`surface-ledger.md`] accounts for every **recon-time
  surface element**; **re-convergence** accounts for surface **found during the hunt** and routes it back.
- [`recall-audit.md`] — the "what did we miss?" reviewer also runs `reconverge.py --validate`; an
  un-converged inbox at close is a REAL-MISS to adjudicate, alongside `shallow-clear`/`untested-surface`.
