# severity-model — the three axes a finding is rated on, and how they reconcile

A finding does not have "a severity". It has THREE axes that answer three different questions, and they
are deliberately not collapsed into one number. Overloading one field to carry all three is what let an
inflated rating ship unchecked (the drift the L-C narrowing closes). This doc defines the axes, the
`severity_basis` / `severity_rationale` fields that reconcile them, and how `_cvss_drift_check` +
`scripts/validate.py` enforce the reconciliation. Read it with its sibling `severity-calibration.md`
(which governs the *metric choices* that feed the vector); this doc governs how the axes relate.

## The three axes

1. **CVSS vector (`cvss_vector`) — arithmetic / supplementary.** Computed DETERMINISTICALLY by
   `scripts/cvss.py` from the metric letters; never hand-overridden. When a rating feels wrong you
   correct the *metrics* and re-derive — you do not type a different number (see severity-calibration.md).
   It is a supplementary, reproducible yardstick, not the headline.
2. **Business `severity` — DEMONSTRATED.** What the evidence actually proved an attacker can do here,
   now, in scope. It rates the demonstrated case, not the best case (`severity-calibration.md` deflation
   guard). This is the axis a client debrief defends.
3. **VRT (`vrt{}`) — governs the bug-bounty headline.** On a program-flagged bug-bounty engagement
   (`scope.yaml program.taxonomy == vrt`) the Vulnerability Rating Taxonomy priority is the submission's
   headline. Governed by `scripts/vrt.py` + `_vrt_governance_check`; absent on an ordinary pentest. Its
   `priority_basis` / `priority_rationale` are the VRT-axis analogue of the fields below.

The three answer different questions — *what does the base vector compute* (CVSS), *what did we prove*
(severity), *what does the program call it* (VRT) — so they legitimately diverge. The reconciliation
fields make the divergence explicit instead of hiding it.

## `severity_basis` — reconciling demonstrated `severity` against the CVSS rating

`severity_basis` (optional; absent ⇒ `baseline`) declares WHY the demonstrated `severity` relates to the
CVSS-computed rating the way it does. It mirrors `vrt.priority_basis`.

- **`baseline`** — `severity` matches the CVSS rating. The default; most findings. Nothing to justify.
- **`demonstrated-vs-potential`** — `severity` is LOWER than the vector's rating because the vector
  expresses the *potential* best-case while `severity` reflects what was demonstrated (a blocked
  precondition, an unseeded DB, a WAF). Pairs with `potential_severity` (the best-case). This is the
  conservative, safe direction.
- **`argued-elevation`** — the demonstrated business `severity` is HIGHER than the raw CVSS arithmetic on
  argued grounds (e.g. a cross-tenant / data-integrity impact the base metrics under-weight). REQUIRES a
  non-empty **`severity_rationale`** stating the argument. This is the ONLY thing that excuses an upward
  divergence — `potential_severity` does not.

## When each axis diverges (and how it is enforced)

`_cvss_drift_check` (in `verify_completion.py`) recomputes every finding's vector and compares the
declared severity's rank to the computed rating's rank (`critical=5 … info=1`; a CVSS `None`/0.0 rating
compares as `info`). A clean match is never drift. A divergence is DRIFT unless EXPLAINED, and the two
directions are **not symmetric**:

- **Deflation** (declared < computed — the report under-states, the safe direction): EXPLAINED by a set
  `potential_severity` (demonstrated-vs-potential). Missing `potential_severity` ⇒ drift.
- **Inflation** (declared > computed — the report over-states vs the arithmetic, the dangerous
  direction): EXPLAINED only by `severity_basis == argued-elevation` WITH a non-empty
  `severity_rationale`. `potential_severity` ALONE no longer excuses it — this is the overload the gate
  used to blanket-skip, letting an inflated severity ship.

Escalation is the usual self-attestation shape: a soft **warning while hunting**, a **HARD fail once the
gates are armed** (a report exists, or the run is terminal with findings).

`scripts/validate.py` enforces the field's *internal* consistency only — it is stdlib-only and does NOT
compute CVSS, so it never checks drift direction (`severity_basis_errors`): the value must be one of the
three; `argued-elevation` requires a non-empty `severity_rationale`; `demonstrated-vs-potential` requires
`potential_severity` to be set. The drift *direction* check is `_cvss_drift_check`'s job alone. The field
is OPTIONAL and additive — a finding without it is `baseline` and completely unaffected.

## Operator rule of thumb

Compute the vector, never type the score. If the demonstrated `severity` ends up *below* the vector,
record the best case in `potential_severity` (`severity_basis: demonstrated-vs-potential`). If you must
rate *above* the arithmetic, you owe an argument — set `severity_basis: argued-elevation` and write the
`severity_rationale`. On a bug-bounty program, also stamp the `vrt{}` headline (see the VRT governance).
Anything else is drift, and the gate will say so.
