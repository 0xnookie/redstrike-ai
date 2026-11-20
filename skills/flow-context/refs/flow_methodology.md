# Flow modeling — methodology

A reference for turning a crawled application into a structured state model: states → actions →
transitions → guards → invariants, keyed to identity/role.
The model is CONTEXT the logic/race/authz executors reason over and the browser driver navigates — never
itself a finding.

## Why a structured model

Business-logic, race-condition, auth-bypass and idor each depend on knowing the app's intended flow.
Without a shared model each one re-derives it ad hoc and shallowly, and the browser driver has no plan to
reach a deep state.
One `flow_context.json` is the shared substrate: model the flow once, reason over it many times.

## The state machine

Think of the app as a state machine.

- A **state** is a page or a resource/cart/checkout/auth condition — a node the user can be in.
- An **action** is something the user can do from a state (a request: method + route + handler).
- A **transition** is an action that moves from one state to another, legitimate only when its **guard**
  holds.
- An **invariant** is a rule the app assumes is always true across the machine.

Model each node with the URL/route that renders it so the browser driver can navigate there, and record
which identities reached it (`reachable_by`) so role differences are visible.

## Actions — what to capture

For each action record method, route, and (white-box) handler.
Then the properties the executors key off:

- `state_change` — does it mutate server state? (the race / logic / CSRF surface)
- `single_use` — is it meant to succeed at most once per subject? e.g. redeem a coupon, withdraw,
  confirm an order (the race over-redemption surface)
- `allowed_roles` — who is the server supposed to let perform it? (the BFLA / vertical surface)
- `non_replayable` — does it ride a non-curl-constructible request (a framework server action with a
  bound-state body)? If so, the executor must replay it from captured traffic, not synthesize it.

## Guards — classify them

A guard is the precondition a transition assumes.
Classify it so the right executor picks it up, and record WHERE it is enforced (`enforced_by`):

- `auth-required` / `role-required` — identity or privilege gate → auth-bypass / privesc
- `ownership` — the subject owns the resource → idor
- `csrf-token` / `state-precondition` / `sequence` — a prior step or token must exist → business-logic
- `payment-confirmed` / `quota` — an economic precondition → business-logic (quota under concurrency →
  race-condition)
- `rate-limit` — throttle on the action → informs race / anti-automation

A guard observed as `client-only` is a lead, not a conclusion: the transition may be reachable by forced
browsing or a direct request — the executor confirms whether the server re-checks it.

## Invariants — the rules to break

Enumerate the rule each workflow assumes.
Each is a hypothesis the downstream executor tries to violate for impact:

- **single-use** — an action succeeds at most once (one-time code, one withdrawal, one vote)
- **ownership** — only the owner reads/writes a resource
- **sequence** — steps run in order; a later step assumes an earlier one completed
- **price-integrity** — total = sum(item.price × qty); the client cannot set the price
- **quantity-nonneg** — amounts/quantities cannot go negative
- **quota** — a limited resource cannot be over-consumed
- **monotonic** — a counter/status only moves one way (pending → paid, never back)
- **role-gate** — an action is reserved to a role
- **uniqueness** / **atomicity** — a key stays unique; a compound update is all-or-nothing

For each, record the concrete `break_impact` (money / access / data / quota) and `route` it to the
executor best placed to prove a violation.

## Workflows — the ordered walk

Name the multi-step workflows (checkout, registration, password-reset, transfer, upgrade) as an ordered
walk over states/actions.
Mark `enforced_order` when steps must run strictly in sequence — an unenforced order is the step-skipping /
forced-browsing surface, and the ordered steps are the browser driver's scripted path to a deep state.

## Identity keying — do it up front

Crawl every flow as each identity and difference the results.
The sensitive flow is often gated behind a verified / paid / second-tenant account a researcher cannot
self-provision; a deep state is simply unreachable without it, so the model has no transitions past that
gate.
Record what identities the flows need in `identity_requirements` so the gap is explicit before the hunt,
not discovered mid-hunt.

## Safety

Walk flows with TEST accounts only.
Keep every state change reversible and do not complete real purchases, transfers, or cross-account
reads during modeling — breaking an invariant is the variant's job, with care, not the feeder's.
