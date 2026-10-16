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
