# Chain + logic reasoner (D2)

Turns the flat candidate list into **candidate attack chains** — the difference between
"here are 30 sinks" and "this LFI plus this writable log is an RCE, and this route has no
authz." Two kinds:

- **technical** — taint/dataflow chains (LFI+log→RCE, SSRF→cloud-metadata, SQLi→cred-reuse).
  Built on the `refs/taint/` reachability candidates.
- **logic / authz** — flaws with **no tainted-data signature** (unauthenticated state change,
  IDOR with no ownership check, mass-assignment→privesc, BFLA on an admin route). Taint can't
  see these; the reasoner finds them in the **structural map**.

A chain_candidate is a **LEAD**, never a finding. source-audit stays a feeder: the chain's
`route_sequence` is an ORDERED plan the hunt executes, each executor proving its leg **and** the
next leg's precondition. This is **pre-proof** (a source hypothesis); `attack-chain-discovery`
is **post-proof** (it composes already-accepted findings). A chain the hunt proves graduates
there — don't double-report.

## The three inputs
1. **taint candidates** — `candidates[]` with `taint.reachable` (from `refs/taint/`).
2. **structural facts** — `structural[]`, extracted by `structural.yaml` (routes, auth-guards,
   id-from-param, mass-assignment, writable paths). These are the **positive** facts.
3. **the pattern catalog** — `patterns.yaml`: named chains with `requires` + `route_sequence`.

## How the reasoner composes (the non-regex half)
For each catalog pattern, check whether its `requires` are satisfiable from (1)+(2). The
load-bearing step semgrep can't do is **confirming a negative**:
- `structural.yaml` finds every `state-change-route` and every `auth-guard`. The reasoner marks a
  state-change-route with **no** guard on/around its handler as `unauth-route` (`source: manual`)
  — by reading the handler, its decorators/middleware, and any blanket before-filter. Only then
  does `unauth-state-change` fire.
- `id-from-param` is a positive fact; `idor-missing-owner-check` fires only after the reasoner
  confirms **no ownership/tenant comparison** exists between the fetch and the response.
- `mass-assignment` fires `mass-assignment-privesc` only if the bound model actually carries a
  privileged field with no allowlist excluding it.

Record the confirmed-vs-assumed split in `preconditions[]`, and set `confidence` accordingly
(high = every leg confirmed/taint-reachable · low = a leg rests on an assumption — say which).

## Emit (schema: chain_candidates[])
```json
{ "id": "scc-001", "pattern": "idor-missing-owner-check", "kind": "logic",
  "title": "IDOR on /invoice — object loaded by request id, no owner check",
  "steps": [ {"ref":"sf-016","role":"entry","note":"Invoice.query.get(request.args id)"},
             {"ref":"sf-017","role":"precondition","note":"no owner==caller check before return"} ],
  "route_sequence": ["idor"],
  "preconditions": ["confirmed: no ownership check in get_invoice"],
  "impact": "Cross-tenant invoice read", "confidence": "medium" }
```
`steps[].ref` points at a `candidates[]` id (`sa-NNN`) or a `structural[]` id (`sf-NNN`).

## Honesty / limits
- semgrep OSS taint is **intra-procedural**; cross-file technical chains and ALL logic chains are
  the reasoner's judgement over the map, not a semgrep match. Rate them as leads, not proofs.
- A chain whose legs you can't tie together from source is **not** a chain — drop it, don't pad
  `chain_candidates[]`. A false chain wastes an executor sequence.
- Never promote a chain_candidate to a finding here (feeder invariant). In a **code-only**
  engagement (no running target) that changes — see the PR3 provisional-finding mode.

## Extending
Add a pattern to `patterns.yaml` (its `route_sequence` items must be in the schema enum) and, if
it needs a new positive fact, a rule to `structural.yaml` tagged with a `metadata.fact` ∈ the
`structural[].kind` enum. Prove new structural rules on a sample before trusting them.
