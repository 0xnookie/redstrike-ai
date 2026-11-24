# HTTP response splitting / header injection (CWE-113 · CWE-93 — the HTTP-response CRLF variant)

Abuse of an HTTP response where a **user-controlled value** (a redirect target, a cookie value, a
reflected request value echoed into a response header) reaches the RESPONSE HEADER block WITHOUT stripping
CR/LF. An injected `\r\n` (often `\n` alone, or an encoded/double-encoded/null-byte-prefixed variant)
starts a NEW header line the attacker controls, or a double `\r\n\r\n` ends the header block and starts a
SECOND HTTP response. This is the HTTP-response form of CRLF injection; distinct from the email-header
variant (`email-injection`) and from body-landing reflection (`xss-*`).

## Prime directive — the header TAKING EFFECT in the RESPONSE is the proof; a 200/302 or a body reflection is NOT
A request that returns `200`/`302` and does not show a validation error after a CRLF-ish payload is **not**
proof — the app may strip CR/LF downstream, the server may reject the header, or the value may land only in
the body. The finding exists only when the attacker-controlled header **actually took effect in the HTTP
response**, confirmed by one of: the injected `X-`/`Set-Cookie` marker header being present in the captured
RAW response-header block, or a genuine second `HTTP/1.x NNN` start-line being parsed from the raw response
(a response split). And it must be **causal**: re-sending the same request WITHOUT the CR/LF makes the
injected header / second response disappear. A payload only **reflected in the response body** is an XSS
question, not this class. Keep every probe benign and self-scoped (a unique cache-buster), the marker header
harmless, never serve a malicious second response to real users.

## The response-generation trust model (what breaks)
A server builds the response by concatenating server-set headers with values derived from the request (a
redirect `Location` from a `?url=`/`?next=` param, a `Set-Cookie` from a preference/session value, a custom
`X-` header echoing a request value). Three assumptions are routinely unprotected:
1. **Header-value integrity** — a user value placed into a response header is not CR/LF-stripped, so
   `%0d%0a` in the value starts a NEW response header line the attacker controls.
2. **Header-set is fixed** — the app assumes only its own headers exist; an injected `Set-Cookie` /
   `X-`-header is added, or an existing one is overridden.
3. **Header/body boundary** — a blank line (`%0d%0a%0d%0a`) ends the header block, so an injected sequence
   can start a second, attacker-shaped HTTP response (response splitting).

## Ingest (from recon)
- `content-discovery/` — params + endpoints, and the observed response-header behaviour (which params echo
  into `Location` / `Set-Cookie` / a custom header).
- `injection-context/injection_context.json` — reflective sinks + injectable param candidates.
- `js-analysis/out/<site>/findings/{endpoints,params}.jsonl` — redirect params (`url`/`next`/`return`/
  `redirect`/`dest`/`callback`) and request values reflected into headers.
- `scope.yaml` — `oob.collaborator` (for an attributable beacon if a split triggers a server-side fetch).

## 1. Map the response-header sinks
Per in-scope param: which RESPONSE header does its value reach?
- **`Location`** — a redirect/`next`/`url`/`return` param is the classic CRLF sink (and the most common
  one that still bites). (Attacker control of the *destination host* itself, without a split, is
  `open-redirect`/`host-header`, not this class.)
- **`Set-Cookie`** — a preference/language/session value reflected into a cookie.
- **A custom/`X-` header** — any request value echoed back into a response header.
Record the param, the sink, the carrier, and the baseline response-header block (no CR/LF) for the
differential.

## 2. Header-add probe (primary benign proof)
Inject a benign marker header. Capture the RAW response headers (`curl -sD- -o /dev/null`):
```
value%0d%0aX-CRLF-Test:rs-crlf-<token>          # full CRLF
value%0aX-CRLF-Test:rs-crlf-<token>             # LF only — common where the app pre-strips CR
value%250d%250aX-CRLF-Test:rs-crlf-<token>      # double-encoded (decoded twice by a proxy/app)
value%00%0d%0aX-CRLF-Test:rs-crlf-<token>       # null-byte-prefixed (naive strip stops at the NUL)
```
**Proof of effect:** `X-CRLF-Test: rs-crlf-<token>` appears in the captured response-header block, and it
DISAPPEARS when the CR/LF is removed (causal differential).

## 3. Set-Cookie injection
```
value%0d%0aSet-Cookie:rs_crlf=1
```
**Proof of effect:** the response carries the injected `Set-Cookie` in its header block (session-fixation
primitive when it sets a session-relevant cookie). Removing the CR/LF drops it.

## 4. Response split (header/body boundary break)
Force a second response. **Always add a unique cache-buster** (`?cb=<rand>`) so only your own request is
affected — never a payload a shared cache would store and serve to others:
```
value%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type:text/html%0d%0aContent-Length:11%0d%0a%0d%0a<b>split</b>
value%0aContent-Length:0%0a%0aHTTP/1.1 200 OK%0a%0aOK     # LF-only split
```
**Proof of effect:** the raw response contains a SECOND `HTTP/1.x NNN` start-line (parse the raw bytes, not
the body as rendered). If a cache/CDN sits in front, confirm the split in isolation and hand the cross-user
cache impact to `cache-poisoning` — do not poison a shared cache here.

## 5. Carrier & encoding notes
- **Carrier matters.** A value reflected onto the wire uses `%0d%0a`; **try LF-only (`%0a`) first** (many
  servers strip CR but not LF), then full CRLF, then double-encoded (`%250d%250a`, where a proxy/app decodes
  twice), then a null-byte prefix (`%00%0d%0a…`).
- **Read the RAW response.** Body reflection is not this class — parse the status line + header block with
  `curl -sD-` or the interceptor's raw view.
- **One self-scoped send.** Each confirmed technique needs a single benign send with a cache-buster — not a
  burst, never a malicious second response served to real traffic.

## 6. Confirm + rate (benign)
Confirmation = the injected header **took effect in the response header block** (or a real second response
started), reproduced (≥2 sends), **causal** (removing the CR/LF restores the normal response), with the raw
header block / parsed split recorded into `poc/<id>/`. Rate by impact:
- **Response split enabling cross-user XSS / cache poisoning** → **High** (coordinate the downstream leg
  with `xss-*` / `cache-poisoning`).
- **Header injection with demonstrated impact** (session fixation via injected `Set-Cookie`, security-
  relevant header override) → **Medium**.
- **Header add with no demonstrated impact** → **Low**.

## De-dup — hand these OFF (don't re-report)
| Observation | Owner |
|---|---|
| A payload that lands/executes in the response **BODY** (reflected/stored HTML/JS) | `xss-*` (a different class) |
| Attacker controls the redirect **destination/host** in `Location` (no header split) | `open-redirect` / `host-header` |
| A poisoned response a shared cache serves **cross-user** | `cache-poisoning` |
| CR/LF into a generated **email** header block (`Bcc`/`Reply-To`/MIME) | `email-injection` |
| The validity/impact of a secret an injected header carries | `secrets` / the owning auth class |
THIS skill keeps the **HTTP response-header manipulation / response split** itself.

## Declining-prevalence note (be honest)
Raw-header CR/LF is of **declining prevalence**: modern web servers, reverse proxies and framework HTTP
layers (and most CDNs) strip or reject bare CR/LF in header values, and many redirect helpers URL-encode or
validate the `Location` value. Expect most targets to be NOT vulnerable; a body-only reflection is common
and is NOT this class. Do not inflate a reflection into a response-split claim — require the header-block /
parsed-split + causal differential before reporting.

## Cleanup
Every probe is a single benign, self-scoped send (unique cache-buster, marker header only). Record in
`cleanup.md` that no shared cache was poisoned and no malicious second response was served to a real user.
Delete any captured response that carries a real secret after fingerprinting.
