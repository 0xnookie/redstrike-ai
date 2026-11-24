# WebSocket (CSWSH / message-layer / socket authz) — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the WebSocket gauntlet. Confirmed = a REAL WebSocket break proven benignly — an
authenticated socket opened CROSS-ORIGIN (CSWSH) whose benign READ frame was accepted / returned the
victim's data, OR a message-layer injection / authz bypass shown by a before/after STATE differential, OR an
unauthenticated connection that executed a PRIVILEGED frame, OR sensitive data captured over `ws://`
cleartext — NOT a bare 101 upgrade. A payload that detonates downstream (XSS/SQLi/cmd) ROUTES to its owning
class, it is not claimed here. Re-run the benign break proof.

## WebSocket false-positive gauntlet (base check #3)
- [ ] **A REAL break — not a bare upgrade.** Evidence shows one of: (CSWSH) a handshake from a
      tester-controlled CROSS-ORIGIN page, carrying the victim's ambient cookie, was accepted AND a benign
      READ frame returned the victim's data; (message-layer / authz-IDOR) a frame violated an invariant with
      a before/after STATE differential (a second identity's object read/changed, a role/privilege-tamper
      frame accepted, a message reaching an injection sink); (missing-auth) an UNAUTHENTICATED connection
      executed a privileged read/action frame; (`ws://`) sensitive data was captured over an unencrypted
      socket. A WebSocket endpoint that merely **upgraded (101)** is `js-analysis`/recon, NOT a finding —
      reject it here.
- [ ] **The security control actually failed.** For CSWSH: the handshake authenticates via an ambient
      **cookie** AND `Origin` is not validated (the browser auto-sent the cookie cross-origin). For
      authz/missing-auth: the object-level / authentication check on the frame is absent, not merely a
      by-design public read. Attacker-controlled input drove it.
- [ ] **Reproducible.** The break reproduces (≥2) with the before/after state (or the accepted cross-origin
      read) captured both times.
- [ ] **De-dup / correct ownership (defer, don't claim).** A payload that **detonates downstream** is the
      owning class's finding: frame content rendered as script → `xss-*`; a frame reaching a SQL backend →
      `sqli-*`; an OS-command frame → `command-injection`; a prototype-pollution JSON frame →
      `prototype-pollution`. This skill proves the frame REACHES the sink / the authz break; the downstream
      detonation is confirmed by that class — do NOT double-claim it. CSWSH is **de-duped vs `csrf`** (CSWSH
      is the WS-handshake analog; an ordinary cross-origin state-changing HTTP form is `csrf`). TLS/cipher on
      `wss://` → `tls-attacks`; bare handshake-token forgery (JWT `alg`/secret/claim, OAuth flow) →
      `jwt`/`oauth` (it counts HERE only as the vehicle for the socket break).
- [ ] **Benign + approved + scope.** CSWSH driven from a tester-controlled page against the tester's OWN
      session (never a real user's); TEST accounts + benign markers only; any test record reverted
      (`cleanup.md`); no message-flood / oversized-frame DoS; any secret the frames carry redacted to a
      fingerprint; approved; in scope.

## CVSS integrity
CSWSH reading sensitive victim data, or an authz/IDOR-over-frames that reads/changes another user's data, or
a missing-auth privileged action → High (Critical when it chains to account takeover / mass data access —
coordinate the downstream leg with the owning class); a message-layer injection that reaches a sink → rate to
the sink actually demonstrated (and route the detonation to its class); `ws://` cleartext of sensitive data →
Medium; `ws://` with no sensitive data → Low. Justify from the confirmed break (accepted cross-origin read /
before-after state), not from the mere existence of a WebSocket endpoint.

Run `scripts/cvss.py "<CVSS vector>"` for any **Medium+** finding to compute the base score (do not hand-assert it); the gate recomputes and flags drift.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|blocked|rejected|needs-evidence", "reviewer": "websocket-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["opened wss://app/notifications from tester page https://attacker.test carrying the tester's own session cookie -> handshake accepted (Origin not validated, cookie-auth) -> benign READ frame {\"op\":\"get_profile\"} returned the tester's email (fingerprinted); reproduced 2/2; de-duped vs csrf (WS-handshake analog); no downstream detonation claimed"],
  "scope_ok": true, "notes": "benign READ only against tester's own session; TEST accounts; no DoS; downstream XSS/SQLi routed to owning class; TLS/token mechanics deferred" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
