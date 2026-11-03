# surface-ledger — track the attack SURFACE, not just the vuln CLASSES

The biggest recall leak the recall work found: **coverage is tracked per vuln category, but recall leaks
through the attack surface.** `coverage_ledger.json` proves which classes ran; it cannot see how much of
the real surface each class was tested against. Recon can discover 20 injectable params and the SQLi
executor test 2 — the category ledger still reads `sqli: attempted, 0 findings`, a clean-looking result
hiding 18 untested params. No category-level gate can see that gap. This ledger closes it.

## What it records
One row per **discovered** surface element (`surface_ledger.schema.json`): its `kind`
(endpoint / param / identity / form / api-operation / sink / header / upload / auth-flow), its `value`,
which recon feeder `discovered_by` it, which categories it is `routed_to`, and its `status`:
- `discovered` — enumerated by recon, **not yet fed to any executor** (a gap if still so at close);
- `tested` — an executor consumed it (recorded in `consumed_by`);
- `skipped` — deliberately not tested (needs a `reason`);
- `n/a` — routes to no in-scope category.

## Lifecycle
1. **Plan** (after recon — ALWAYS, every engagement): `python scripts/surface.py --plan --engagement <dir>`
   reads the feeders (host-discovery, content-discovery, js-analysis, authz-context) and enumerates every
   element as `discovered`, routing each by kind to the categories that should test it. **`--plan` is
   idempotent**: re-running it preserves every element's progress (`tested`/`skipped`/`consumed_by`) and
   appends only newly-discovered elements, so it is safe to emit early and re-emit as late feeders
   (authz-context identities, js-analysis) — and any surface found mid-hunt — are added.
   (`--fresh` forces a clean rebuild.)
2. **Mark** (during the hunt): as an executor consumes an element,
   `surface.py --mark <id> --status tested --by <skill>` (or `--status skipped --reason …`).
3. **Validate / gate**: `surface.py --validate --engagement <dir>` — a `discovered` routed element, or a
   `skipped` one with no reason, is a gap (exit 2).

## How it composes (why it is the capstone)
It upgrades the two prior recall fixes from inference to fact:
- **Recall audit (#4)** previously inferred "high-prior" from category-level signals. Now it reads this
  ledger and reports each discovered-but-untested element as a concrete **`untested-surface`** miss — not
  "this class probably had surface", but "THIS param was discovered by content-discovery and tested by
  nobody".
- **Escalation ladder (#3)** closes an empty surface only after its ladder; this says WHICH surfaces
  existed to close.

## Gate posture (strict — universal emission)
The surface ledger is emitted on **every** engagement (step 1 is mandatory after recon and idempotent),
so the gate is now strict. Once a consolidated report exists, `verify_completion.py --engagement`:
- **hard-fails if the ledger is MISSING** — a report with no surface ledger means surface coverage was
  never tracked (the juice-shop-2026-10-20 blind spot), no longer a soft warning;
- validates a present ledger **strict**, so an untested routed element, a `skipped`-without-reason
  element, **or an empty-but-present ledger** (feeders didn't populate it) all fail.
During the hunt (before a report exists) a missing ledger is a soft nudge to emit it, not a failure. This
mirrors how `_coverage_hard_errors` treats the coverage ledger: soft while hunting, hard at report time.
