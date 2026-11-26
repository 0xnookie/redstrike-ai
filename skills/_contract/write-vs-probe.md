# Write vs. Probe — the enforceable line (imported where an executor sends a non-safe request)

Two opposite field failures share one root cause: no crisp definition of what counts as a
*production write*.

- **The un-deletable prod write.** An executor fired a real, state-persisting write "to prove" a
  finding — into production, with no way to undo it. A plain GET readback had *already* confirmed the
  finding; the write proved nothing new and left permanent attacker-authored state behind.
- **The wrongly-blocked benign probe.** The gate blocked a request that could not change any state at
  all (a safe-method read, or a body the server rejects before persisting), reading it as a "write"
  and burning turns. A probe that cannot persist is not an exploitation step and must not be gated as
  one.

This file draws the line so the same evidence standard never does either again.

## Definition

A request is a **PROBE** (not a production write) **only if it cannot create, modify, or delete
persistent state** that outlives the request. It is proven to be a probe by **one** of:

1. **Safe method** — `GET` / `HEAD` / `OPTIONS` / `TRACE` with no state-changing side effect. (Note:
   a safe *method* is not automatically safe if the endpoint mutates on read — judge the effect, not
   the verb alone.)
2. **Validation-FAILING body** — the request is shaped so the server rejects it *before* it reaches
   the persistence layer (a deliberately invalid value, a type error, a tripped required-field /
   schema / auth check). The *rejection itself* is the signal; nothing is stored.
3. **Immediately-reversed write** — a write that is undone in the same action via a **recorded
   `delete_path`** (the exact route/command/id that reverses it), captured in the approval entry
   *before* the write and executed right after. Without a recorded `delete_path` this is **not** a
   probe — it is a production write (see `roe-gate.md` §2).

Anything else — a write whose persistence is not prevented (1,2) or not reversed (3) — is a
**production write**: it needs the exploitation approval gate, and under `no_destructive` it needs
per-action approval regardless.

## Declaration

An executor that sends a non-safe request declares its intent inline and in the finding evidence:

```
intent: probe
basis: safe-method | validation-failing-body | reversible-self-write
justification: <why this request cannot persist state — the readback already confirms X, so no
                production write is needed; or: the body fails validation at <check>; or: reversed
                via delete_path <...>>
```

`intent: write` (no probe basis) means a real production write — it goes through the approval gate,
and `basis: reversible-self-write` additionally requires the recorded `delete_path`.

## The order that prevents the incident

**Confirm with the least-persistent evidence first.** Before any write-to-prove, ask: *does a
read/probe already confirm this?* A GET readback, a boolean/timing differential, a validation-failing
response, or an existing accepted finding is sufficient evidence — a write adds nothing and cannot be
undone. **A write-to-prove is a last resort, and only ever as a reversible-self-write with a
`delete_path` probed and recorded first.** Probe for the delete route *before* you write; if you
cannot find one, you do not write.

## Gate framing (both directions)

- A request that meets a probe basis above is **not** an exploitation action — do **not** block it as
  one (that is the wrongly-blocked-benign-probe failure; see `roe-gate.md` §6 "wrongly-blocked
  benign probe").
- A write with no probe basis **is** a production write — it does **not** get to ride in as a "probe"
  (that is the un-deletable-prod-write failure).
