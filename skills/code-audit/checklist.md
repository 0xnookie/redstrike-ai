# Code Audit — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Repo resolved from `scope.source.local_path` (default `engagements/<id>/source/`) + in-scope confirmed
- [ ] RoE honored; approval obtained BEFORE any dynamic PoC / fuzz-harness run (static reasoning is read-only)
- [ ] `source-audit/source_context.json` leads ingested (candidates + chain_candidates[] + structural[])

## Model
- [ ] App model built: entry points, trust boundaries, auth/session model, data stores, privileged ops → app_model.json

## Surface inventory (completeness — not just per-lead)
- [ ] Full white-box surface enumerated into the surface ledger: EVERY entry point + EVERY source_context.json lead (candidate/structural/chain/priv-op) + EVERY high-risk file + EVERY state-changing op×invariant (`state-op`, from app_model.state_ops) + EVERY route×required-privilege cell (`authz-route`, from app_model.authz_routes) (`python scripts/surface.py --plan --engagement <engagement>`)
- [ ] Large repo handled: risk-prioritized, chunked reasoning plan so size never causes a silent skip (no element dropped for scale)
- [ ] Each surface element closed: marked `tested` (confirmed/ruled-out/open-proof-gap) OR `skipped` with an explicit reason — nothing silently untested (`surface.py --mark`)

## Reason (beyond grep)
- [ ] Inter-procedural taint: each lead traced source→sink across files/functions; sanitizers/guards/auto-escape on the path named; sanitization-BACKBONE modeled (which serializer/field-type/encoder invokes the shared sanitizer vs the OUTLIER type that skips it)
- [ ] Each lead closed confirmed / ruled-out / open-proof-gap (a grep hit with no traced path is REFUTED, not kept)
- [ ] Non-grep classes reasoned vs the app model: authz (object + function-level), logic invariants, insecure defaults, crypto/deser misuse, SSRF, path traversal, injection, race conditions, mass assignment, framework-tier/architectural-promise invariants (an advertised tier/promise — "runs no server code", "sandboxed", "read-only field" — not enforced on a pipeline into a privileged location)
- [ ] **Business-logic-invariant pass ran (§3a):** state-changing ops enumerated into app_model.state_ops, each with the invariant it must hold (single-use/limit/quota/stock/price/ownership/idempotency), checked for check-then-act-without-lock (TOCTOU/race), double-spend, client-trusted values re-derived server-side, and **lax-setter/strict-finalizer** staged-state eligibility (value staged by a cheap endpoint then consumed by a finalizer — don't flag the lax setter; confirm/refute via the finalizer's enforcement←severity←validator←wired-in chain), lock-SCOPE vs concurrency domain (a per-host flock/mutex/local cache does NOT rule out a race on a cluster — check the lock backend + its default), and DB-constraint backstop + migration-history (a UNIQUE/CHECK/FK once added then DROPPED leaves a check present-in-code but unenforced) — every `state-op` element closed (no state-op left `discovered`)
- [ ] **Authorization-matrix pass ran (§3b):** every route/handler × its required privilege enumerated into app_model.authz_routes (incl. framework/default ACL), flagging any state-changing/sensitive route with NO authz AND any route that bypasses a central authz backstop (service/queue/raw-SQL around the framework ACL), AND any authz-model-MUTATION endpoint (set-privileges/grant-role/change-tier) that lets the actor grant beyond their own authority or writes a client-controlled privilege field, via two-identity + role-matrix reasoning — every `authz-route` element closed (no authz-route left `discovered`)
- [ ] Counterevidence pass run (negative control where feasible); runtime-guard uncertainty recorded per candidate

## Demonstrate (white-box evidence standard)
- [ ] Each finding carries a traced reachable path at file:line AND a PoC/exploit sketch (or an executed PoC / fuzz-triggered crash)
- [ ] Confidence calibrated: static-only path ⇒ `probable` + runtime-guard caveat; `confirmed` only with dynamic proof
- [ ] CVSS rated (scripts/cvss.py) with potential_severity where a precondition blocked full demonstration

## Chain
- [ ] Confirmed weaknesses composed into kill-chains, EACH leg a confirmed finding → chains.jsonl
- [ ] No padded chains — any chain with an unconfirmed leg was dropped

## Fuzz hand-off
- [ ] Fuzzable entry points picked from source + confirmed candidates
- [ ] Per-language harness stubs + input grammar/seed hints emitted → fuzz_targets.jsonl (handed to the fuzzing skill)

## Emit
- [ ] findings.json (schema-valid; empty array → a clean repo is a valid PASS)
- [ ] poc/ per finding (trace + PoC sketch / dynamic evidence)
- [ ] report.md

## Completeness gate + re-convergence
- [ ] Surface found mid-audit folded in (app_model.json / reconvergence/inbox.jsonl) and re-planned — no un-routed mid-audit discovery
- [ ] `python scripts/surface.py --validate --engagement <engagement> --routed-to code-audit --strict` passes — every entry point / lead / high-risk file / state-op / authz-route `tested` or reasoned-`skipped`
- [ ] Any remaining `discovered` element reported as an explicit RECALL GAP (partial coverage: coverage %, what's pending) — never a silent clean, never partial-as-complete

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason; reviewer confirms surface-ledger closure (coverage rubric)
