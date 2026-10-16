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
