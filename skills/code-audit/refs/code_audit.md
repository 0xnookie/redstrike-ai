# Code audit — the reasoning arsenal (beyond grep)

White-box PROVING. `source-audit` already grepped + ran taint and routed candidates into `source_context.json`;
this agent READS the real code paths to CONFIRM or REFUTE them, reasons about classes a pattern scan can't
assert, and chains confirmed weaknesses. The deliverable is a traced path + a demonstration, not a pattern hit.
Read-only while reasoning; any dynamic step is approval-gated. Redact secret values; hand deps to `cve-intelligence`.

## 1. Model the app FIRST (the frame every judgment needs) → `app_model.json`
You cannot judge authorization or business logic without a model of intent. Build it before tracing:
- **Entry points** — HTTP routes/handlers, GraphQL resolvers, RPC/queue consumers, scheduled jobs, CLI, webhooks,
  framework lifecycle hooks. Each is an untrusted-input boundary. Record `file:line` + the handler symbol.
- **Trust boundaries** — where data crosses from attacker-controlled to trusted (request→service→store, service→
  service, tenant→tenant, user→admin). Note what AUTHN/AUTHZ each boundary is supposed to enforce.
- **Auth / session model** — how identity is established (session cookie / token / header), how roles/scopes are
  represented, and WHERE the check lives (middleware, decorator, per-handler, ORM scope, none). Build the
  identity × capability intent: who is SUPPOSED to be able to do what.
- **Data stores + privileged operations** — DBs, caches, object stores, secret stores; the operations that must
  be gated (money movement, role change, data export, deploy, impersonation, file write/exec).
Suggested `app_model.json` shape (object): `{ "entry_points": [{file,line,symbol,method,route,auth_expected}],
"trust_boundaries": [...], "auth_model": {mechanism, role_repr, guard_sites:[...]}, "data_stores": [...],
"privileged_ops": [{op, guarded_by, file, line}], "state_ops": [{op, invariant, file, line,
concurrency_control}], "authz_routes": [{method, route, required_privilege, authz, file, line}],
"high_risk_files": ["path", {file, reason}] }`. The `high_risk_files` list is where you record files you deem
high-risk during modeling (crypto, deserializer, auth middleware, raw-query builder) that no `source-audit` lead
points at — so the surface inventory below folds them in too. `state_ops` and `authz_routes` are the two
FIRST-CLASS enumerated surfaces of sections 3a/3b — you fill them while modeling so the business-logic-invariant
pass and the authorization-matrix pass each become an enumerated, gated work-list (not sink-driven leads).

## 1b. Inventory the FULL surface + close every element (completeness, not just per-lead) → surface ledger
Per-LEAD closure (section 2) alone lets the audit finish having only looked at the leads `source-audit` happened
to route — silently missing entry points / sinks / files no lead covered. That is the recall leak this step
closes. REUSE the same surface-ledger mechanism the recon feeders use (`scripts/surface.py`), do not reinvent it:
- **Enumerate** — after the app model, `python scripts/surface.py --plan --engagement <engagement>` reads
  `app_model.json` (entry points, privileged ops, **`state_ops`**, **`authz_routes`**, `high_risk_files`) +
  `source-audit/source_context.json` (candidates `sa-*`, structural facts `sf-*`, chain candidates `scc-*`) and
  writes one ledger row per element — kinds `entry-point` / `source-lead` / `high-risk-file` / **`state-op`**
  (a state-changing op + the invariant it must hold, §3a) / **`authz-route`** (a route × its required
  privilege, §3b), all routed to the `code-audit` consumer. `state-op` and `authz-route` make the two
  invariant/matrix passes FIRST-CLASS enumerated surfaces — gated and coverage-tracked exactly like a sink lead,
  so a skipped invariant or an un-enumerated route is a visible RECALL GAP, not a silent miss (grep cannot see
  "no lock" or "no authz annotation"). The high-risk-file set is DERIVED from the leads/entry points/state-ops/
  authz-routes, so it is bounded by the surface, not by repo size. `--plan` is idempotent: re-run it whenever you
  add an entry point / state-op / authz-route / high-risk file to `app_model.json` or find new surface
  mid-audit — it preserves progress and appends only the new elements.
- **Close each element** — as you finish reasoning about an element, mark it:
  `scripts/surface.py --mark <id> --status tested --by code-audit --reason "<closure>: …"` where the closure is
  `confirmed` / `ruled-out` / `open-proof-gap` (mirrors the `analysis.jsonl` closure), OR
  `--mark <id> --status skipped --reason "<why not reasoned about>"` (e.g. generated/vendored code out of scope).
  An element left `discovered` is one you never looked at — a **RECALL GAP**, not a skip.
- **Gate before done** — `scripts/surface.py --validate --engagement <engagement> --routed-to code-audit --strict`
  must pass (exit 0). The `--routed-to code-audit` slice means you gate only YOUR surface, so in a combined
  grey+white-box engagement a sibling executor's still-pending black-box surface in the same shared ledger does
  not block you (and vice-versa). The report-time engagement gate validates the WHOLE ledger strict.
- **Honest coverage** — `--validate --json` reports a `coverage` figure (`pct` closed, `open_gaps`). Put that
  figure in `report.md`. If the repo can't be fully covered in one pass, say so explicitly (coverage %, what's
  pending) — never present partial coverage as complete.

### Large-repo robustness (so a huge repo doesn't cause silent skips)
A 29k-file monolith cannot be read end-to-end in one pass, and "ran out of budget" must never silently become
"clean". Make enumeration systematic and reasoning risk-prioritized + chunked:
- The surface ledger is the work-list: it enumerates a BOUNDED, de-duplicated set (entry points + routed leads +
  their files), not every file — so even a massive repo yields a finite inventory to close.
- Order by risk: reachable, auth-reachable, or taint-reachable entry points + leads first; then authz-sensitive
  files (routes/guards/id-reads/mass-assign/writable/exec paths); then the rest. Close the ledger in that order.
- Chunk the reasoning (per module / per entry-point cluster) and persist progress via `--mark` after each chunk,
  so an interrupted run resumes from the ledger instead of restarting or silently dropping the tail.
- If you genuinely cannot close every element, STOP and report partial coverage: the unclosed elements stay
  `discovered` and the `--validate` gate surfaces them as RECALL GAPs — a truthful "partial" beats a false "clean".
- Re-convergence: surface found mid-audit (a new entry point, a new sink, an internal host from an SSRF lead) is
  appended to `app_model.json` / `reconvergence/inbox.jsonl` and re-planned, so the inventory grows to a fixpoint.

## 2. Inter-procedural, framework-aware taint (confirm/refute each lead) → `analysis.jsonl`
A grep/taint scanner marks a sink "present" or "reachable" intra-file; it misses cross-file/cross-function flow,
framework auto-escaping, and context-sensitive sanitizers. For each `source_context.json` candidate (and any new
source you find), TRACE by reading:
- Follow the user-controlled value from the ENTRY POINT through every call, assignment, wrapper, and framework
  binding to the SINK — across files and functions. Record the call chain as `file:line` hops.
- At each hop, NAME any sanitizer / encoder / validator / type-coercion / framework auto-escape and decide if it
  neutralizes THIS value in THIS context (an HTML encoder does nothing for a SQL sink; a validator on a sibling
  field is irrelevant; a guard that runs AFTER the sink fires is too late; fail-open in a `try/except` doesn't
  sanitize). Per `_contract/counterevidence.md`: a safe sibling, a too-late control, a different-route control,
  and "a helper handles it" (unchecked) do NOT rule a candidate out.
- **Framework awareness** — know the defaults: ORM parameterization vs raw/string-built queries; template
  auto-escaping on vs raw/`|safe`/`dangerouslySetInnerHTML`; body-parser/mass-assign binding; default CSRF /
  auth middleware and the routes that OPT OUT. The vuln is usually where code LEAVES the safe default.
- Close each candidate: **confirmed** (traced unsanitized path to a dangerous sink) · **ruled-out** (a control on
  the path neutralizes it — cite it) · **open-proof-gap** (reachable-looking but a precondition blocks proof).
`analysis.jsonl` record (one per candidate): `{id, class, source:{file,line,param}, sink:{file,line,kind},
call_chain:[{file,line,note}], controls:[{file,line,kind,effective,why}], closure:"confirmed|ruled-out|
open-proof-gap", confidence, runtime_guard_uncertainty, lead_ref}`.

## 3. Classes a scanner can't ASSERT (reason against the model)
- **Broken / missing authorization (object-level / IDOR)** — a handler reads an object by a client-supplied id
  and never checks the identity OWNS it (no `where owner = current_user`, no tenant scope). Trace: entry → id read
  → store query → response. The absence is the finding; confirm it with two identities in the PoC.
- **Missing function-level authz (privesc)** — a privileged operation reachable by a lower role because the
  role/scope guard is absent, on the wrong route, or opt-out. Cross-check `app_model.auth_model.guard_sites`
  against `privileged_ops` — a privileged op with no guard site covering its route is the finding.
- **Business-logic invariant violations** — model the intended invariant (price ≥ 0, one coupon per order, balance
  never negative, state machine order) and find the path that breaks it (negative quantity, re-applied discount,
  skipped step, TOCTOU on a limit). Needs the model; grep cannot see intent.
- **Insecure defaults / misconfig in code** — debug on, permissive CORS built in code, default/weak secret,
  disabled cert check, overly broad permission grant, verbose errors.
- **Crypto misuse** — ECB, static/reused IV/nonce, hardcoded/predictable key, unauthenticated encryption,
  homemade MAC, `==` token compare (timing), weak hash for passwords/signatures. (JWT crypto → `jwt`.)
- **Unsafe deserialization** — attacker bytes into a native deserializer / unsafe loader reachable from an entry
  point → `deserialization` to prove; here, trace reachability + gadget availability.
- **SSRF / path traversal / injection** — a user-controlled URL/host the server fetches; a user path into a
  file read/include/write; user data into a command/query/template interpreter — all traced inter-procedurally.
- **Race conditions** — a check-then-act / limit / single-use action with no lock/transaction/idempotency key
  where concurrent requests break the invariant.
- **Mass assignment** — a bind/merge of request body straight into a model/record with no allow-list, letting a
  client set fields it shouldn't (role, owner, price, flags). → confirm reachable sink + unguarded field set.

## 3a. Business-logic & concurrency invariants (the "break an intended invariant" pass) → `state-op` surface
Sections 2–3 are sink-driven: they start from a value flowing to a dangerous sink. The two sharpest logic bugs
have NO sink and NO pattern — an unauthenticated redemption-limit check with no lock, a price re-trusted from the
client — so grep/taint are blind to them. This pass is NOT lead-driven: you ENUMERATE the app's state-changing
operations and, for each, the invariant it must hold, then try to break it. Record each as a `state_ops` row in
`app_model.json` so it becomes an enumerated, gated `state-op` surface element (one ledger row to close), not a
lucky find.
- **Enumerate the state-changing operations.** Walk the entry points + privileged/data-store writes and list
  every operation that MUTATES shared or valuable state: redeem / apply-coupon or voucher, checkout / pay /
  refund, transfer / withdraw / top-up, place or cancel order, book / reserve / consume stock, register /
  change-email, change-role / grant, vote / rate, increment a counter or quota, consume a one-time token
  (reset / invite / OTP), finalize a workflow step. Each gets a `state_ops` row `{op, invariant, file, line,
  concurrency_control}`.
- **Name the invariant each MUST hold.** Pick from (at least): **single-use** (a token/coupon redeems once);
  **redemption / usage limit** (≤ N uses per user/order/global); **quota** (≤ the plan/tier allowance); **stock**
  (never oversell below 0); **price-integrity** (server-side price, total = Σ line items, no negative / rounding
  gain); **ownership** (the actor owns the object it mutates); **idempotency** (a replay / double-submit does not
  double-apply); **monotonic counter** (a sequence/balance only moves the intended direction, never negative).
- **Try to break it — three recurring ways:**
  1. **Check-then-act without a lock / atomic conditional update / unique constraint → TOCTOU / race.** The code
     reads the current state (remaining uses, balance, stock), decides it is OK, then writes — with the read and
     the write in separate statements/transactions and no row lock (`SELECT … FOR UPDATE`), no atomic
     conditional update (`UPDATE … WHERE remaining > 0`), no unique constraint, no idempotency key. Concurrent
     requests each pass the check before any writes land, so the invariant breaks (coupon redeemed N times, limit
     exceeded, balance goes negative). The absence of the lock/atomic-update/constraint on the write path IS the
     finding — confirm the window by reading the two code points, and demonstrate with the `race-condition` skill
     (concurrent requests, before/after state, serial baseline does NOT reproduce). An UNAUTHENTICATED such
     operation is worse — it needs no account to hammer.
  2. **Double-spend / replay.** The same token / nonce / request can be submitted twice because it is not marked
     consumed atomically with its effect (or not marked at all) — reset tokens, gift-card codes, idempotency-less
     payment capture, one-time invites.
  3. **Client-trusted value not re-derived server-side.** Price, total, discount %, quantity sign, user_id,
     role, tier, `is_admin`, currency — taken from the request and used in the decision instead of being looked
     up / recomputed from server state. Negative quantity, zero/negative price, a discount re-applied, a tier the
     client named — each breaks the invariant with no "injection" anywhere.
- **Close it** like any element: `confirmed` (the invariant is breakable — cite the check line + the write line +
  the missing control) / `ruled-out` (a lock / atomic update / unique constraint / server-side re-derivation
  holds it — cite it) / `open-proof-gap`. Then `surface.py --mark <state-op id> --status tested …`. A state-op
  left `discovered` is a RECALL GAP — an invariant you never reasoned about.

## 3b. Authorization matrix (two-identity + role-matrix reasoning) → `authz-route` surface
Missing authorization is an ABSENCE — there is no annotation to grep for, and a central ACL backstop can hide a
route that bypasses it. So build the matrix explicitly and enumerate it: every route/handler × the privilege it
SHOULD require. Record each cell as an `authz_routes` row in `app_model.json` so it becomes a gated `authz-route`
surface element — the matrix is now a work-list you must close, not a hope that a lead happened to cover the
unguarded route.
- **Enumerate every route/handler × its required privilege.** For each entry point, write the cell
  `{method, route, required_privilege, authz, file, line}`: who is SUPPOSED to be able to call it (public /
  authenticated-any / owner / role:X / admin), and WHERE the check that enforces that actually is (middleware /
  decorator / attribute / per-handler / ORM or data-access-layer scope / **none**). Include framework/default-based ACL:
  routes a framework guards by convention or by a default-deny list, and — critically — the routes that OPT OUT
  of it or were never added to it.
- **Flag the two absences that matter:**
  1. **A state-changing or sensitive route with NO authz** (missing BFLA / function-level check) — a privileged
     op reachable by a lower role (or unauthenticated) because the guard is absent, on the wrong route, or
     opted-out. Cross-check `auth_model.guard_sites` and the framework's default ACL against each cell: a
     sensitive cell whose `authz` resolves to nothing is the finding.
  2. **A route that BYPASSES the central authz backstop.** Many frameworks enforce authorization at a choke
     point — a data-access-layer write/read ACL, a policy middleware, a permission-checked service facade. A
     handler that reaches the same effect by a DIFFERENT path — calling the underlying service/repository
     directly, enqueuing a job, or issuing raw SQL — SKIPS that backstop and its ACL. Enumerate, for each
     sensitive op, whether the handler goes THROUGH the choke point or AROUND it; an around-path with no local
     guard is the finding (this is exactly the missing-ACL BFLA grep/taint can't see — the backstop makes the
     code "look" protected).
- **Two-identity + role-matrix reasoning.** Judge each cell against ≥2 identities (e.g. a low-priv user and the
  resource owner / an admin): can identity A invoke a cell reserved for B? That difference, demonstrated, is the
  BFLA/privesc PoC (hand the dynamic proof to `bola-bfla` / `privesc`; object-level ownership to `idor`). Keep
  object-level (does A reach B's object) distinct from function-level (does A reach an admin FUNCTION at all).
- **Close it:** `confirmed` (cite the route + the absent/bypassed guard + the two-identity reasoning) /
  `ruled-out` (an effective guard covers the cell — cite its site) / `open-proof-gap`, then
  `surface.py --mark <authz-route id> --status tested …`. An `authz-route` left `discovered` is a RECALL GAP — a
  matrix cell you never checked.

## 4. Chaining confirmed weaknesses → `chains.jsonl`
Compose CONFIRMED findings (not candidates) into higher-impact kill-chains, **each leg a confirmed finding**:
- IDOR (read another user's record) + mass-assignment (set `role`) → account takeover / privesc.
- SSRF (server fetches attacker URL) + cloud metadata reachability → credential theft.
- Path traversal (write) + a code/exec path over the written file → RCE.
- Auth-bypass + a privileged op with no second check → full compromise.
Each `chains.jsonl` record: `{id, name, impact, legs:[{finding_id, role_in_chain}], precondition_notes}`. Every
`finding_id` MUST resolve to a confirmed entry in `findings.json`. A chain with any unconfirmed/assumed leg is
DROPPED (it may be seeded to `attack-chain-discovery` only as a candidate, never emitted as a finding here).
These confirmed chains SEED `attack-chain-discovery`, which composes cross-skill accepted findings post-review.

## 5. Evidence + confidence discipline (what the reviewer enforces)
- A finding = **(a)** a traced reachable path at `file:line` across the call chain + **(b)** a PoC/exploit sketch
  (or executed PoC / fuzz crash). Both halves, every time.
- Static-only path ⇒ `confidence: probable` + a stated runtime-guard uncertainty; `confirmed` needs dynamic proof.
- Precondition-blocked exploitation ⇒ demonstrated `severity` + `potential_severity`, confidence honest.
- Negative control where feasible: a benign variant of the request is handled correctly while the malicious one
  isn't — the difference is attributable to the bug, not noise.
- Evidence files go under `poc/<id>/` (e.g. `trace.md` with the annotated path, `poc.md`/`poc.*` the sketch or
  driver, dynamic output). Cite them in the finding's `evidence[]`.
