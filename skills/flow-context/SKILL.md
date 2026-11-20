# Flow Context (shared feeder)

> RECON / context feeder for the application-logic family (variants: `business-logic`,
> `race-condition`, `auth-bypass`, `idor`). Needs MULTIPLE identities (≥2 accounts; +admin for
> vertical). Lightly active → honors `_contract/roe-gate.md`. Emits NO findings → `review.md` only.
> Output: `flow_context.json` (schema `_contract/flow_context.schema.json`).

## Interview

- **STEPS:** load identities → map states/pages (crawl as each identity) → enumerate the actions reachable from each state → model the transitions + their guards → extract the invariants each flow assumes → name the multi-step workflows → route → emit → review.
- **TOOLS:** interceptor with multi-session (`auth.env`), `jq` over `js-analysis` + `content-discovery`, request-diff across identities, a headless browser to walk deep flows.
- **GOAL:** Build the structured application state model — states → actions → transitions → guards → invariants, keyed to identity/role — into `flow_context.json`, so `business-logic`, `race-condition`, `auth-bypass` and `idor` reason over ONE shared model instead of each re-deriving the flow ad hoc, and the browser driver has a navigation plan to act on. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `states.json`, `transitions.json`, `invariants.json`, `flow_context.json`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = `content-discovery/` multi-step flows + `js-analysis/out/<site>/findings/{endpoints,params,apis}.jsonl` + `auth.env` (**≥2 identities + roles**) + `scope.yaml`. Chains FROM `content-discovery` / `js-analysis`; chains TO `business-logic`, `race-condition`, `auth-bypass`, `idor`.
- **DECOMPOSITION:** n/a (feeder).

## Goal

Produce the shared flow context: the app state machine (states + actions + transitions + guards) plus the invariants each workflow assumes, keyed to identity/role.
DONE = `checklist.md` `- [x]` · `review.md` PASS (`flow_context.json` validates against the schema).

## What do we want

- States/pages: the nodes of the app state machine, each with its URL/route (the browser driver's navigation plan) and which identities reach it
- Actions per state: method/route/handler, who is allowed to perform them, whether they change state or are single-use
- Transitions: which action moves from which state to which, under what guard/precondition — and whether the guard is enforced server-side or client-only
- Invariants: the rules each flow assumes (single-use, ownership, sequence, price integrity, quota, role gate) + the impact if broken, routed to the executor that proves a violation

## Steps  (action · tool · output)

1. Load identities from `auth.env` (≥2; +admin) · read · (into context)
2. Map states/pages (crawl each flow as each identity; record URL + `reachable_by`) · multi-session interceptor + browser · `states.json`
3. Enumerate the actions reachable from each state (method/route/handler; `state_change`, `single_use`, `allowed_roles`) · `jq`/crawl · `states.json`
4. Model transitions + their guards (`guard_kind`, `enforced_by`) by walking flows as each identity · request-diff · `transitions.json`
5. Extract the invariants each workflow assumes (+ `break_impact`, `route`) · synth · `invariants.json`
6. Name the multi-step workflows (ordered walk over states/actions; `enforced_order`) · synth · (into context)
7. Consolidate + validate vs schema · synth · `flow_context.json`
8. Emit summary · synth · `summary.md`
9. /REVIEW SKILL · `review.md`

**Flag non-replayable actions (for the consuming executor).** Where an action rides a Next.js / RSC
**server action** (a POST with a `Next-Action` header + a bound-state `multipart/form-data` body — **not**
curl-constructible from scratch), set `non_replayable: true` on it in `states.json` and note that the
downstream `business-logic` / `race-condition` / `auth-bypass` / `idor` test must **source the request from
`proxy-context/http_history.json`** (captured via browser-through-proxy, `_contract/proxy.md` §4a) and
**replay/tamper** it — walk the transition in the browser, don't synthesize it. The feeder only records this;
it breaks no invariant and crosses no account (that's the variants).

## Tools

- multi-session interceptor (Caido/mitmproxy with 2+ profiles), `jq`/`grep` over `js-analysis` + `content-discovery`, request-diff, a headless browser to walk deep flows
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs

- `content-discovery/`: mapped multi-step flows; `js-analysis/out/<site>/findings/`: `endpoints.jsonl`, `params.jsonl`, `apis.jsonl`
- `auth.env`: **≥2 identities + roles** (attacker low-priv + victim; +admin for vertical)
- `scope.yaml`

## Outputs

`states.json` · `transitions.json` · `invariants.json` · `flow_context.json` · `summary.md` · `logs/`

## Phases

- **Phase 1 (generic):** identity load + state/page + action enumeration.
- **Phase 2 (target-specific):** transition + guard modeling + invariant extraction + workflow naming + consolidation.

## Identity requirements — scope them UP FRONT (a test account's *level* caps what's modelable)

Logic / race / authz reasoning needs ≥2 identities — but also the **right level**. The sensitive flow is
often gated behind a **verified identity** (eID / ID-Austria / KYC / a paid tier a basic self-serve account
lacks), and a deep state (checkout past payment, an admin workflow) is **unreachable** without an account of
the needed level — so the model has no transitions past that gate to key to it. Before promising a logic/race
hunt, state what identities the flows actually need: how many, which roles/tenants, and **what verification
level** — and flag when a flow is **unmodelable** without operator-provisioned identities (a researcher
usually can't self-provision eID, and email verification blocks self-registering a throwaway). Record this in
`flow_context.json` (`identity_requirements`) so the gap is explicit, not discovered mid-hunt.

## Safety

Mapping/crawl only — walk flows with TEST accounts, don't break an invariant or cross an account during
modeling (that's the variants, with care). Keep state changes reversible; don't complete real
purchases/transfers. Scope-gate; audit-log.
