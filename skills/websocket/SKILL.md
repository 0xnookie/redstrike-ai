# WebSocket Agent  (WebSocket security — CSWSH / message-layer / socket authz)

> ATOMIC single agent — the WebSocket (WS/WSS) attack surface. Cross-Site WebSocket Hijacking (CSWSH),
> message-layer injection over frames (XSS/SQLi/cmd/JSON role-tamper), authz/IDOR over frames, missing
> auth on the socket, and `ws://` cleartext. Consumes `js-analysis` (the `new WebSocket(...)` / `ws(s)://`
> endpoints) + `auth-context` (cookie-vs-token on the handshake).
> ACTIVE (opens sockets + sends frames), findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.

## De-dup boundary (what this skill OWNS vs hands off)
- **OWNS — the WebSocket surface proven as a REAL break:** (a) **CSWSH** — an authenticated socket opened
  CROSS-ORIGIN (an attacker-origin handshake carrying the victim's ambient cookie auth) whose benign READ
  frame is accepted / returns the victim's data; (b) **message-layer injection / authz-IDOR over frames** —
  a frame carrying another identity's object id, a role/privilege-tamper JSON frame, or a missing
  object-level check, shown by before/after state; (c) **missing auth on the socket** — an unauthenticated
  connection accepted AND a privileged read/action frame succeeds; (d) **`ws://` cleartext** — sensitive
  data observed over an unencrypted socket (benign capture).
- **HANDS OFF:** a payload that **detonates downstream** routes to the OWNING class — frame content rendered
  as script in the browser → `xss-*`; a frame reaching a SQL backend → `sqli-*`; a frame reaching an OS
  command → `command-injection`; prototype-pollution via a JSON frame → `prototype-pollution`. This skill
  proves the frame REACHES the sink / the authz break; the downstream detonation is **confirmed by the
  owning class, not double-claimed here**. CSWSH is **de-duped vs `csrf`** (CSWSH is the WS-handshake analog;
  ordinary cross-origin state-changing HTTP forms stay with `csrf`). TLS/cipher on `wss://` → `tls-attacks`;
  bare handshake-token forgery (JWT `alg`/secret/claim, OAuth flow) → `jwt`/`oauth` (it counts HERE only as
  the vehicle for the socket break).
- A WebSocket endpoint that merely **upgrades (101)** is RECON, NOT a finding — this skill must show a real
  break (CSWSH read accepted / message-layer or authz break by before-after state / missing-auth privileged
  frame / cleartext sensitive data).

## Interview
- **STEPS:** ingest `ws(s)://` / `new WebSocket(...)` endpoints from `js-analysis` + the handshake auth model (cookie vs token) from `auth-context` → map per endpoint (what authenticates the handshake, what the frames do, which frames are state-changing) → CSWSH: open the socket from an attacker origin with the victim's ambient cookie + send a benign READ frame → message-layer: inject over frames (XSS/SQLi/cmd/JSON role-tamper) + authz/IDOR with a second identity → missing-auth: connect unauthenticated + attempt a privileged frame → `ws://` cleartext check → confirm a REAL break benignly (before/after state or accepted cross-origin read) → route any downstream detonation to the owning class → rate → emit → review → verify.
- **TOOLS:** a WS client (`websocat` / `wscat` / browser `WebSocket`), interceptor (WS frame view), a tester-controlled cross-origin page (for CSWSH — `_contract/browser-session.md` when a real browser is needed), OOB (`interactsh`), `curl`/`jq`, `refs/websocket.md`; hand frame-rendered script to `xss-*`, SQL/command frames to `sqli-*`/`command-injection`, TLS to `tls-attacks`, token mechanics to `jwt`/`oauth`.
- **GOAL:** Confirm a WebSocket break — an authenticated cross-origin handshake accepted (CSWSH), a message-layer injection / authz bypass shown by before/after state, a missing-auth privileged frame, or `ws://` cleartext — proven benignly. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `ws_tests.jsonl`, `callbacks.jsonl`, `findings.json`, `poc/`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/out/<site>/findings/endpoints.jsonl` (the `ws(s)://` + `new WebSocket(...)` endpoints) + `auth-context/auth_context.json` (session mechanism — cookie flags vs token — on the handshake) + `scope.yaml` (`oob.collaborator` + ≥2 tester identities for frame-authz). `refs/` = `websocket.md`. Chains FROM `js-analysis`/`auth-context`; chains TO `reporting` (+ `xss-*`/`sqli-*`/`command-injection` for a downstream-detonating frame, `csrf` de-dup on CSWSH).
- **DECOMPOSITION:** n/a (atomic).

## Goal
Prove a WebSocket break, benignly: a cross-origin authenticated handshake accepted (CSWSH), a message-layer
injection / authz bypass shown by before/after state, a missing-auth privileged frame, or `ws://` cleartext
— not a bare 101 upgrade. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## What do we want
- The WS endpoints + the handshake auth model: does the socket authenticate via an ambient **cookie**
  (CSWSH-prone — the browser auto-sends it on the upgrade) or a **token** in the first message / query
  (CSWSH-resistant)? Is `Origin` validated?
- A REAL break: a cross-origin handshake carrying the victim's cookie whose benign READ frame is accepted
  (CSWSH); or a frame that violates an invariant with before/after state (authz/IDOR over frames, role
  tamper, message injection reaching a sink); or an unauthenticated privileged frame; or sensitive data in
  cleartext over `ws://`
- Benign proof — the accepted cross-origin read, or the before/after state differential — NOT a bare 101
  upgrade, NOT the executor's assertion; any secret the frames carry redacted to a fingerprint; a downstream
  detonation routed to its owning class

## Steps  (action · tool · output)
1. Ingest `ws(s)://` / `new WebSocket(...)` endpoints + the handshake auth model (cookie vs token, Origin check) · `jq` js-analysis + auth-context · (into tests)
2. Map per endpoint: what authenticates the handshake, the frame protocol, which frames read vs change state · WS client + interceptor · `ws_tests.jsonl`
3. CSWSH: open the socket from a tester-controlled attacker origin carrying the victim's ambient cookie; send a benign READ frame (`_contract/browser-session.md` if a real browser is required) · browser / WS client · `ws_tests.jsonl`
4. Message-layer injection: send frames with XSS/SQLi/cmd/JSON role-tamper payloads; observe the reply + downstream effect (benign) · WS client + OOB · `ws_tests.jsonl`
5. Authz/IDOR over frames: with a second identity, send a frame referencing identity A's object id; check cross-identity read/change (before/after) · WS client (two sessions) · `ws_tests.jsonl`
6. Missing auth: connect WITHOUT credentials; attempt a privileged read/action frame · WS client · `ws_tests.jsonl`
7. `ws://` cleartext: confirm the socket is unencrypted + carries sensitive data (benign capture) · interceptor · `ws_tests.jsonl`
8. Confirm a REAL break benignly (accepted cross-origin read / before-after state / privileged unauth frame / cleartext capture); route any downstream detonation to the owning class · synth + OOB · `poc/<id>/`, `callbacks.jsonl`
9. Rate (CVSS) + write finding · synth · `findings.json`
10. Emit report · synth · `report.md`
11. /REVIEW · `review.md` · 12. /VERIFY · `verify.md`

## Tools
- a WS client (`websocat` / `wscat` / browser `WebSocket`), interceptor (WS frame view), a tester-controlled cross-origin page for CSWSH, OOB (`interactsh-client`), `curl`/`jq`, `refs/websocket.md`
- browser-gated CSWSH / stateful frame writes: `_contract/browser-session.md` (login → navigate → action; benign markers; revert)
- hand off: frame content rendered as script → `xss-*`; SQL-backend frame → `sqli-*`; OS-command frame → `command-injection`; prototype-pollution JSON frame → `prototype-pollution`; TLS on `wss://` → `tls-attacks`; bare token forgery → `jwt`/`oauth`; ordinary HTTP-form CSRF → `csrf`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/out/<site>/findings/endpoints.jsonl` (the `ws(s)://` + `new WebSocket(...)` endpoints — do NOT re-run js-analysis, consume its output)
- `auth-context/auth_context.json` (session mechanism — cookie flags vs token — on the handshake; Origin-validation posture)
- `scope.yaml` (`oob.collaborator` + ≥2 tester identities for frame-authz), `refs/websocket.md`

## Outputs
`ws_tests.jsonl` · `callbacks.jsonl` · `findings.json` · `poc/` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** WS endpoint + handshake-auth-model ingest (cookie vs token, Origin check) + frame-protocol mapping + the CSWSH / missing-auth / cleartext probe set.
- **Phase 2 (target-specific):** CSWSH cross-origin read + message-layer injection + authz/IDOR-over-frames (two identities) + benign before/after confirmation + downstream routing + rating (approval-gated).

## Safety
Opening a socket and sending frames is an **active** test; a state-changing frame performs REAL actions —
**approval-gated**; confirm with BENIGN effects only (a benign READ frame for CSWSH, a benign marker / no-op
frame, a benign test record reverted after). CSWSH is driven from a **tester-controlled** cross-origin page
against the tester's OWN authenticated session (never a real user's); use TEST accounts + benign markers
only, and record/revert any test record created (`cleanup.md`). Do NOT run message-flood / oversized-frame
**DoS**. A downstream-detonating payload (XSS/SQLi/cmd) is handed to its owning class — don't weaponize it
here. CSWSH is de-duped vs `csrf`; TLS → `tls-attacks`; token mechanics → `jwt`/`oauth`. Redact any secret
the frames carry to a fingerprint. A WS upgrade that resets with no HTTP status, or a sudden block, is a
HALT-and-FLAG signal (`_contract/anti-automation-ladder.md`) — never fake a client to beat it. Kill switch;
scope to authorized WS endpoints; rate-limit; audit-log.
