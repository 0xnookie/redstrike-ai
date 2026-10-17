# Race-condition techniques
# Benign + minimal + bounded concurrency (tens, not thousands). Test account. Revert state. Not a DoS test.

## Where races live (hunt these)
- **Limit-overrun** (one request is allowed, N should not be): coupon / gift-card redemption, OTP /
  password-reset token use, withdrawal / transfer / purchase, vote / like / follow / rating, invite /
  referral / signup bonus, registration uniqueness, "claim" / "apply" once-only actions.
- **TOCTOU** (check-then-use gap): balance check → debit, stock check → provision, permission check →
  act, "verify" → "confirm". The window between the check and the write is the target.
- **Multi-step**: start purchase → apply coupon → fire N parallel "confirm". **Multi-endpoint**:
  /cart → /checkout with a parallel final step.

## Collapse the window — the single-packet attack
- **HTTP/2 single-packet attack** (best): send ~20–30 requests in ONE TCP packet so the server receives
  them simultaneously, removing network-jitter skew. Burp **Turbo Intruder** `Engine.BURP2` with a gate,
  or Repeater → "Send group in parallel (single-packet attack)".
- **HTTP/1.1 last-byte sync**: send all requests but withhold the final byte of each; then flush the last
  bytes together so they complete at once.

Turbo Intruder skeleton (bounded):
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.BURP2)
    for i in range(20):                      # BOUNDED — tens, not thousands
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')                 # release all at once
def handleResponse(req, interception):
    table.add(req)
```

## Framework/stack specifics
- **PHP session lock**: `session_start()` locks the session file, serialising requests on one PHPSESSID.
  Bypass with a DIFFERENT PHPSESSID per concurrent request (or no session) so they run truly parallel.
- **DB isolation**: READ COMMITTED (default) without `SELECT ... FOR UPDATE` / unique constraint →
  racy. SERIALIZABLE / row locks / atomic `UPDATE ... WHERE` / `ON CONFLICT` → resistant (expect failures).
- **Modern surfaces**: GraphQL batch (one POST, ~20 aliased mutations), gRPC concurrent frames,
  WebSocket message bursts, serverless concurrent invocations (reserved-concurrency checks).

## Confirm (benign)
Compare FINAL STATE against the serial baseline: redemption count, balance, stock, account/row count,
number of valid tokens. The state delta — not the HTTP status — is the proof. Keep a test account, bound
concurrency, and revert (refund/void/delete) afterward. Tools: Turbo Intruder, Burp Repeater parallel.

---

## Extended arsenal — limit-overrun vs TOCTOU taxonomy

| Class | The window | Example | Serial baseline |
|---|---|---|---|
| Limit-overrun | between N parallel reads of a counter and the write-back | redeem 1 coupon → N redemptions | blocks (409 / limit hit) |
| TOCTOU | between a check and the dependent write | balance-check → debit; stock-check → ship | blocks |
| Partial-construction | a row exists before its guard field is written | confirm against a null/empty token | blocks |
| Hidden sub-state | a brief intermediate state during a multi-step write | act while "pending" | blocks |

A finding requires the serial baseline to BLOCK and only the parallel burst to break it.

---

## Extended arsenal — sub-state & single-endpoint race classes

- **Single-endpoint, varied input**: race e.g. `email=a@test` against its verify so the verified flag
  binds to the wrong value.
- **Partial construction**: fire "confirm" the instant before the token/owner field is written, so the
  guard reads null → confirmed without the secret.
- **Idempotency-key bypass**: reuse the same `Idempotency-Key` across parallel workers with a slightly
  changed body — some stores de-dupe only AFTER the effect.
- **2FA / step-up flag race**: a session minted before the MFA flag is enforced is usable in the window.
- **OAuth code / refresh redemption**: redeem one `authorization_code` / refresh token N times in parallel.
- **Multi-session**: N distinct sessions (different cookies/tokens) racing the same per-user limit.

---

## Extended arsenal — connection warming & timing hygiene

- **Warm the connection** first (cheap in-scope request / TLS handshake) so setup cost isn't in the window.
- **Disable Nagle** (`TCP_NODELAY` off) so withheld bytes flush together in HTTP/1.1 last-byte sync.
- Prefer HTTP/2 single-packet — it removes the network jitter that last-byte sync only approximates.
- **Negative / overlapping timestamps** in Turbo Intruder output (response starts before the request
  finished sending) confirm the requests were genuinely concurrent.
- Re-fire the bounded burst to control for luck — races are probabilistic.

---

## Extended arsenal — Turbo Intruder race patterns

```python
# Gate with DISTINCT inputs (single-endpoint varied-input race), bounded:
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.BURP2)
    for val in wordlists.clipboard[:20]:                 # BOUNDED — tens, not thousands
        engine.queue(target.req, val, gate='g')
    engine.openGate('g')
    engine.start(timeout=10); engine.complete(timeout=60)
# HTTP/1.1 last-byte sync when HTTP/2 isn't available:
#   engine = RequestEngine(..., engine=Engine.THREADED)   # withhold + flush the final bytes together
```
- Burp Repeater: group the tabs → "Send group in parallel (single-packet attack)".

---

## Extended arsenal — sleep / timing-based window detection

- Before racing for impact, confirm a window EXISTS: send a parallel pair and compare total wall-time to
  the serial sum — overlap (parallel ≈ one request) means the critical section isn't serialised.
- If an endpoint accepts a benign delay (large in-scope input / a slow related call), it widens the window
  and makes a tight race reproducible — note it, keep it bounded, never DoS.
- Stay benign: tens of requests, a TEST account, REVERT state; prove the break by before/after STATE with
  the serial baseline NOT reproducing it.
