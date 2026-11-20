# Race Condition Agent

> ATOMIC single agent (no feeder) — TOCTOU + limit-overrun races on state-changing actions.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval** (state change). Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** identify race windows (single-use / limited actions + TOCTOU check-then-use) → craft concurrent requests (HTTP/2 single-packet / HTTP/1 last-byte sync) → fire a bounded burst → detect over-redemption / double-spend / limit bypass → confirm benignly on a TEST account → rate → emit → review → verify.
- **TOOLS:** Turbo Intruder (single-packet attack), Burp Repeater "send group in parallel", interceptor, `refs/race_techniques.md`.
- **GOAL:** Confirm a race condition — a concurrency-induced violation of an intended invariant (a single-use action succeeding more than once, a balance/stock going inconsistent) — benignly and minimally. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `race_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/` endpoints+forms + `business-logic` workflow model (single-use/limited actions) + `flow-context/flow_context.json` + `scope.yaml`. `refs/` = `race_techniques.md`. Chains FROM recon / `business-logic` / `flow-context`; chains TO `reporting`.
- **DECOMPOSITION:** n/a (atomic).

## Goal
Prove a race condition (limit-overrun / TOCTOU), benign + minimal. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## What do we want
- A state-changing action with an intended limit or a check-then-act gap: coupon/gift-card redemption, OTP/reset-token use, withdrawal/transfer, vote/like/follow, invite/referral, registration uniqueness, MFA step
- The concurrency method that collapses the window (single-packet attack for HTTP/2; last-byte sync for HTTP/1.1)
- A benign proof on a TEST account: the limited action succeeded N>1 times (or an invariant broke) because requests were parallel — and serial attempts do NOT reproduce it

## Steps  (action · tool · output)
1. Ingest endpoints/forms + business-logic single-use/limited actions + `flow_context.json` `actions[] where single_use==true && state_change==true` + `invariants[] where route=="race-condition"` (pre-identified over-redemption / limit-overrun targets) · `jq` · (into tests)
2. Pick targets: TOCTOU (check-then-use) + limit-overrun (single-use/quota) · refs · `race_tests.jsonl`
3. Baseline serially (confirm the action is normally limited) · interceptor · `race_tests.jsonl`
4. Fire a BOUNDED concurrent burst (single-packet HTTP/2 via Turbo Intruder, or last-byte sync HTTP/1) · Turbo Intruder · `poc/<id>/` — if the action is a **non-replayable server action** (flagged by `flow_context.json` `actions[].non_replayable`; see note), source the request from `proxy-context/http_history.json` and fire THAT captured request as the parallel burst
5. Detect the break (redeemed >1×, double balance, duplicate unique, bypassed quota) vs serial baseline · synth · `race_tests.jsonl`
6. Confirm benignly + minimally on a test account; revert any state (refund/void) · synth · `cleanup`/`poc`
7. Rate (CVSS) + write finding · synth · `findings.json`
8. Emit report + PoC script · synth · `report.md`, `curl_commands.sh`
9. /REVIEW · `review.md` · 10. /VERIFY · `verify.md`

**Non-replayable server-action targets.** When the single-use / limited action is a Next.js / RSC **server
action** (a POST with a `Next-Action` header + a bound-state `multipart/form-data` body — **not**
curl-constructible from scratch, a synthesized POST 500s), **source the request from
`proxy-context/http_history.json`** — captured once via browser-through-proxy (`_contract/proxy.md` §4a) —
and **fire that captured request as the parallel burst** (bound-state part unchanged), rather than
synthesizing the concurrent requests. Turbo Intruder / the Repeater parallel group drives the captured
request; `scripts/replay_server_action.py` extracts the entry. First invoke the `browser-exploit` capability
(`skills/browser-exploit/`, `_contract/browser-session.md`, approval-gated) to drive + capture the single-use
action autonomously (login→navigate→action), then fire that capture as a PARALLEL BURST (bound-state
unchanged); it hands back the proven finding (under this class) + a replay-faithful capture — de-dupe against
this candidate. Degrade to a human capture only if no browser driver is available.

## Tools
- Turbo Intruder (`Engine.BURP2`, single-packet gate), Burp Repeater parallel group, interceptor, `refs/race_techniques.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/` endpoints+forms, `business-logic` workflow model, `scope.yaml`
- `flow-context/flow_context.json`: `actions[] where single_use==true && state_change==true` + `invariants[] where route=="race-condition"` + `actions[].non_replayable`

## Outputs
`race_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** identify limited/TOCTOU actions + serial baseline.
- **Phase 2 (target-specific):** bounded concurrent burst + confirm the break + rating (approval-gated).

## Safety
Benign + minimal: demonstrate ONE over-redemption / invariant break on a TEST account, then revert the
state (void/refund/delete). **Bound concurrency** (tens, not thousands) — this is a correctness proof, NOT
a load/DoS test; never exhaust connection pools or flood a shared service. No real financial movement.
Approval-gated for state changes; scope-gate; audit-log.
